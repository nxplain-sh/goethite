// Shared by the server script and the tests.
export const API_PORT = 18153
export const DNS_PORT = 18154
// A fixed token in goethite's format (gth_ and 64 hex digits): goethite
// keeps only its SHA-256 hash.
export const TOKEN = `gth_${'0123456789abcdef'.repeat(4)}`
