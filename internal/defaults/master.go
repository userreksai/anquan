// Package defaults holds the deployment defaults shared by the agent and installer.
package defaults

// DefaultMasterAddress is used when no Master IP is selected at build time.
const DefaultMasterAddress = "172.22.0.27"

// MasterAddress is the address used by a newly installed agent. anqu-build can
// override it through the linker without changing the source checkout.
// The configuration TCP port and reporting UDP destinations remain independent.
var MasterAddress = DefaultMasterAddress
