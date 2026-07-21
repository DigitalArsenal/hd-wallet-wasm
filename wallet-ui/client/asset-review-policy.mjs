// Public projection of release/protocol/asset-review-v1.json. The canonical
// release policy must change first; the bundle-boundary test rejects drift.
const metersPerSourceUnit = Object.freeze({
  cm: 0.01,
  km: 1_000,
  m: 1,
  mm: 0.001,
});

const reviewedTransform = Object.freeze({
  metersPerSourceUnit,
  quaternionNormTolerance: 0.000001,
  scaleComponentExclusiveMin: 0,
  scaleComponentInclusiveMax: 1_000_000,
  translationComponentAbsMax: 1_000_000,
  upAxes: Object.freeze(['X_UP', 'Y_UP', 'Z_UP']),
});

export default Object.freeze({ reviewedTransform, schemaVersion: 1 });
