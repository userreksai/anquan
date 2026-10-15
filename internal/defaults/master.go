// Package defaults holds the deployment defaults shared by the agent and installer.
package defaults

// MasterAddress is the fixed address used by a newly installed agent.
// The configuration TCP port and reporting UDP destinations remain independent.
const MasterAddress = "172.22.0.27"
