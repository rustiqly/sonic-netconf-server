package lib

type Authenticator interface {
	Authenticate() bool
	Authorize(cmd string, cmdArgs string) bool
	Account(cmd string, cmdArgs string) bool
}
