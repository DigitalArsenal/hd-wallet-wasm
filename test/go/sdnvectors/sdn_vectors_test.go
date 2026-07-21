package sdnvectors

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type registryBinding struct {
	ClientID      string `json:"clientId"`
	RequestOrigin string `json:"requestOrigin"`
}

type wireCase struct {
	AccountIndex               uint32           `json:"accountIndex"`
	AccountXpub                string           `json:"accountXpub"`
	AuthenticationKeyID        string           `json:"authenticationKeyId"`
	AuthenticationPublicKeyHex string           `json:"authenticationPublicKeyHex"`
	ApprovalKeyID              string           `json:"approvalKeyId"`
	ApprovalPublicKeyHex       string           `json:"approvalPublicKeyHex"`
	CanonicalEnvelope          string           `json:"canonicalEnvelope"`
	IdentityScheme             string           `json:"identityScheme"`
	Name                       string           `json:"name"`
	Operation                  string           `json:"operation"`
	Request                    map[string]any   `json:"request"`
	RegistryBinding            *registryBinding `json:"registryBinding"`
	SeedProfile                string           `json:"seedProfile"`
	SignatureHex               string           `json:"signatureHex"`
	SignatureProfile           string           `json:"signatureProfile"`
	SignedDigestSHA256         string           `json:"signedDigestSha256"`
}

type fixture struct {
	SchemaVersion            uint32     `json:"schemaVersion"`
	AuthenticationCases      []wireCase `json:"authenticationCases"`
	AuthorityActivationCases []wireCase `json:"authorityActivationCases"`
	DecisionCases            []wireCase `json:"decisionCases"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	body, err := os.ReadFile("../../fixtures/sdn-operation-wire-v1.json")
	if err != nil {
		t.Fatalf("read immutable wire fixture: %v", err)
	}
	var value fixture
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("parse immutable wire fixture: %v", err)
	}
	if value.SchemaVersion != 1 {
		t.Fatalf("schemaVersion = %d", value.SchemaVersion)
	}
	return value
}

func decodeHex(t *testing.T, value string, size int, label string) []byte {
	t.Helper()
	if value != strings.ToLower(value) || len(value) != size*2 {
		t.Fatalf("%s is not exact lowercase %d-byte hex", label, size)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %s: %v", label, err)
	}
	return decoded
}

func decodeBase64URL32(t *testing.T, value string, label string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		t.Fatalf("%s is not canonical 32-byte base64url", label)
	}
	return decoded
}

func cloneMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input)+8)
	for key, value := range input {
		result[key] = value
	}
	return result
}

func stringField(t *testing.T, object map[string]any, field string) string {
	t.Helper()
	value, ok := object[field].(string)
	if !ok {
		t.Fatalf("%s is not a string", field)
	}
	return value
}

func canonicalEnvelope(t *testing.T, testCase wireCase) ([]byte, []byte) {
	t.Helper()
	request := cloneMap(testCase.Request)
	var message []byte

	switch testCase.Operation {
	case "sdn.auth.raw-challenge.v1":
		message = decodeBase64URL32(t, stringField(t, request, "challengeBase64url"), testCase.Name+" challenge")
		if testCase.CanonicalEnvelope != "" || testCase.SignedDigestSHA256 != "" {
			t.Fatalf("%s raw lane contains canonical fields", testCase.Name)
		}
		return nil, message

	case "sdn.auth.jcs-envelope.v2":
		if testCase.RegistryBinding == nil {
			t.Fatalf("%s missing compiled registry projection", testCase.Name)
		}
		challenge := decodeBase64URL32(t, stringField(t, request, "challengeBase64url"), testCase.Name+" challenge")
		challengeDigest := sha256.Sum256(challenge)
		delete(request, "challengeBase64url")
		request["challengeSha256"] = hex.EncodeToString(challengeDigest[:])
		request["clientId"] = testCase.RegistryBinding.ClientID
		request["requestOrigin"] = testCase.RegistryBinding.RequestOrigin
		request["identityScheme"] = testCase.IdentityScheme
		request["keyId"] = testCase.AuthenticationKeyID
		request["kind"] = "sdn-login"
		request["signatureProfile"] = testCase.SignatureProfile

	case "sdn.asset-review.authority-activation.v1":
		request["kind"] = "asset-review-authority-activation"

	case "sdn.asset-review.decision.v1":
		request["identityScheme"] = testCase.IdentityScheme
		request["keyId"] = testCase.ApprovalKeyID
		request["kind"] = "asset-review-attestation"
		request["purpose"] = "asset-review-approval"
		request["signatureProfile"] = testCase.SignatureProfile

	default:
		t.Fatalf("%s has unknown operation %q", testCase.Name, testCase.Operation)
	}

	canonical, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal %s independently: %v", testCase.Name, err)
	}
	if string(canonical) != testCase.CanonicalEnvelope {
		t.Fatalf("%s canonical envelope mismatch\nwant %s\n got %s", testCase.Name, testCase.CanonicalEnvelope, canonical)
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != testCase.SignedDigestSHA256 {
		t.Fatalf("%s signed digest mismatch", testCase.Name)
	}
	return canonical, digest[:]
}

func verifyCase(t *testing.T, testCase wireCase) {
	t.Helper()
	_, message := canonicalEnvelope(t, testCase)
	publicHex := testCase.AuthenticationPublicKeyHex
	keyID := testCase.AuthenticationKeyID
	if strings.HasPrefix(testCase.Operation, "sdn.asset-review.") {
		publicHex = testCase.ApprovalPublicKeyHex
		keyID = testCase.ApprovalKeyID
	}
	publicKey := decodeHex(t, publicHex, ed25519.PublicKeySize, testCase.Name+" public key")
	digest := sha256.Sum256(publicKey)
	if "sha256:"+hex.EncodeToString(digest[:]) != keyID {
		t.Fatalf("%s key ID mismatch", testCase.Name)
	}
	signature := decodeHex(t, testCase.SignatureHex, ed25519.SignatureSize, testCase.Name+" signature")
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		t.Fatalf("%s Ed25519 signature failed", testCase.Name)
	}
}

func TestFrozenSdnVectorsVerifyWithoutWasmOrThirdPartyPackages(t *testing.T) {
	vectors := loadFixture(t)
	if len(vectors.AuthenticationCases) != 6 || len(vectors.AuthorityActivationCases) != 1 || len(vectors.DecisionCases) != 2 {
		t.Fatalf("unexpected exact case counts: auth=%d activation=%d decision=%d",
			len(vectors.AuthenticationCases), len(vectors.AuthorityActivationCases), len(vectors.DecisionCases))
	}
	seen := make(map[string]bool, 9)
	for _, group := range [][]wireCase{
		vectors.AuthenticationCases,
		vectors.AuthorityActivationCases,
		vectors.DecisionCases,
	} {
		for _, testCase := range group {
			if seen[testCase.Name] {
				t.Fatalf("duplicate case %q", testCase.Name)
			}
			seen[testCase.Name] = true
			verifyCase(t, testCase)
		}
	}
	if len(seen) != 9 {
		t.Fatalf("verified %d cases, want 9", len(seen))
	}
}
