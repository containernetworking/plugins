package leasepool

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type LeaseStatus int

const (
	Free     LeaseStatus = 0
	Reserved LeaseStatus = 1
	Active   LeaseStatus = 2
)

type Lease struct {
	IP         net.IP           // The IP of the Lease
	Status     LeaseStatus      // Are Reserved, Active or Free
	MACAddress net.HardwareAddr // Mac Address of the Device
	ClientID   []byte           // ClientID of the request
	Hostname   string           // Hostname From option 12
	Expiry     time.Time        // Expiry Time
}

// leaseMarshal is a mirror of Lease used for marshalling, since
// net.HardwareAddr has no native marshalling capability.
type leaseMarshal struct {
	IP         string
	Status     int
	MACAddress string
	ClientID   string
	Hostname   string
	Expiry     time.Time
}

func (l Lease) MarshalJSON() ([]byte, error) {
	return json.Marshal(leaseMarshal{
		IP:         l.IP.String(),
		Status:     int(l.Status),
		MACAddress: l.MACAddress.String(),
		ClientID:   hex.EncodeToString(l.ClientID),
		Hostname:   l.Hostname,
		Expiry:     l.Expiry,
	})
}

func (l *Lease) UnmarshalJSON(data []byte) error {
	stringUnMarshal := leaseMarshal{}
	err := json.Unmarshal(data, &stringUnMarshal)
	if err != nil {
		return err
	}

	l.IP = net.ParseIP(stringUnMarshal.IP)
	l.Status = LeaseStatus(stringUnMarshal.Status)
	if stringUnMarshal.MACAddress != "" {
		l.MACAddress, err = net.ParseMAC(stringUnMarshal.MACAddress)
		if err != nil {
			return fmt.Errorf("error parsing MAC address: %v", err)
		}
	}
	l.ClientID, err = hex.DecodeString(stringUnMarshal.ClientID)
	if err != nil {
		return fmt.Errorf("error decoding clientID: %v", err)
	}
	l.Hostname = stringUnMarshal.Hostname
	l.Expiry = stringUnMarshal.Expiry

	return nil
}

func (l Lease) Equal(other Lease) bool {
	if !l.IP.Equal(other.IP) {
		return false
	}

	if int(l.Status) != int(other.Status) {
		return false
	}

	if l.MACAddress.String() != other.MACAddress.String() {
		return false
	}

	if !bytes.Equal(l.ClientID, other.ClientID) {
		return false
	}

	if l.Hostname != other.Hostname {
		return false
	}

	if !l.Expiry.Equal(other.Expiry) {
		return false
	}

	return true
}
