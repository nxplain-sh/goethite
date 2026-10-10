// Shared by the server script and the tests.
export const API_PORT = 18153
export const DNS_PORT = 18154
export const DOT_PORT = 18155
export const DOH_PORT = 18156
export const DOQ_PORT = 18157
// A fixed token in goethite's format (gth_ and 64 hex digits): goethite
// keeps only its SHA-256 hash.
export const TOKEN = `gth_${'0123456789abcdef'.repeat(4)}`
// A second goethite, a cluster member (e2e/serve-member.mjs).
export const MEMBER_API_PORT = 18158
export const MEMBER_DNS_PORT = 18159
export const MEMBER_CLUSTER_PORT = 18160
// Where its config file says the other member is; nothing listens there.
export const ABSENT_PORT = 18161
