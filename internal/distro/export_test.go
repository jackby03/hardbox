package distro

// TestDetectFromPaths exposes the internal detectFromPaths function for use in
// tests outside this package. It is only compiled during testing.
var TestDetectFromPaths = detectFromPaths
