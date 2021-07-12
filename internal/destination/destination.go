package destination

import "github.com/psanford/cloudtrail-tattletail/config"

type Loader interface {
	Type() string
	Load(c config.Destination) (Destination, error)
}

type Destination interface {
	Send(name, desc string, rec map[string]interface{}, matchObj interface{}) error
	ID() string
	Type() string
}
