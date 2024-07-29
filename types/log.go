package types

type Log struct {
	Topics  []Hash
	Data    []byte
	Address Address
}
