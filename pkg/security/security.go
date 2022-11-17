package security

import (
	"fmt"
	"github.com/opencontainers/selinux/go-selinux"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

type SecurityModule interface {
	PrepareSecurityModule() error
	RequiresReboot() bool
	ReRunCommandWithSecurityLabels(addLinkString string, tmpName string, mtu int, nsFd int, multique bool, mac string) error
}

type NoSecurityModel struct {
}

type SELinuxSecurityModel struct {
}

func GetSecurityModule() SecurityModule {
	if selinux.EnforceMode() != -1 {
		return SELinuxSecurityModel{}
	}
	return NoSecurityModel{}
}

func (sm NoSecurityModel) PrepareSecurityModule() error {
	return nil
}
func (sm NoSecurityModel) RequiresReboot() bool {
	return false
}
func (sm NoSecurityModel) ReRunCommandWithSecurityLabels(addLinkString string, tmpName string, mtu int, nsFd int, multique bool, mac string) error {
	return nil
}

func (sm SELinuxSecurityModel) PrepareSecurityModule() error {
	output, err := exec.Command("getsebool", "container_use_devices").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run getsebool command %s: %v", string(output), err)
	}
	if strings.Contains(string(output), "off") {
		output, err := exec.Command("setsebool", "-P", "container_use_devices", "true").CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to run setsebool command %s: %v", string(output), err)
		}
	}
	return nil
}
func (sm SELinuxSecurityModel) RequiresReboot() bool {
	return true
}

// This is a workaround for a SELinux issue when creating taps in containers.
// The tap device must be created with approperiate SE Linux labels, which the plugin is missing.
// To achieve this we run another copy of the plugin with the required labels applied. This will
// create the tap device from a process with the correct labels. The controll then returns to the
// main instance of the plugin which performs the rest of the configuration.
func (sm SELinuxSecurityModel) ReRunCommandWithSecurityLabels(addLinkString string, tmpName string, mtu int, nsFd int, multique bool, mac string) error {
	// Apply the appropriate se linux label. This will affect the newly executed plugin process.
	if err := selinux.SetExecLabel("system_u:system_r:container_t:s0"); err != nil {
		return fmt.Errorf("failed set socket label: %v", err)
	}
	minFDToCloseOnExec := 3
	maxFDToCloseOnExec := 256
	// we want to share the parent process std{in|out|err} - fds 0 through 2.
	// Since the FDs are inherited on fork / exec, we close on exec all others.
	for fd := minFDToCloseOnExec; fd < maxFDToCloseOnExec; fd++ {
		syscall.CloseOnExec(fd)
	}

	args := []string{addLinkString, tmpName, strconv.Itoa(mtu), strconv.Itoa(nsFd), strconv.FormatBool(multique), mac}
	output, err := exec.Command(os.Args[0], args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run a nested plugin call (%s %s) to add link: %s: %v", os.Args[0], strings.Join(args, ", "), output, err)
	}
	return nil
}
