package ipcert

// this error indicates disruption of ZeroSSL' service
type ZeroSSLError struct{}

func (z *ZeroSSLError) Error() string {
	return "Och! ZeroSSL's service is down!"
}
