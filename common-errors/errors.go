package commonerrors

import "fmt"

// ErrInvalidArgument indicates that the request violated a constraint that was annotated or documented
// in the service definition. This always represents a client bug.
type ErrInvalidArgument struct {
	Field   string
	Message string
}

func (e *ErrInvalidArgument) Error() string {
	return fmt.Sprintf("invalid argument for field %s: %s", e.Field, e.Message)
}

// ErrPermissionDenied indicates that the client is not authorized to make the request because it did not provide
// the correct set of data.
type ErrPermissionDenied struct {
	Message string
}

func (e *ErrPermissionDenied) Error() string {
	return fmt.Sprintf("permission denied: %s", e.Message)
}
