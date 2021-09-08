module github.com/web3zerotrust/signer

go 1.17

require (
	github.com/libs4go/crypto v0.0.0-20210723035624-62aa97055ac2
	github.com/libs4go/encoding v0.0.0-20210720054946-fe0a4a6f4c7a
	github.com/libs4go/errors v0.0.3
	github.com/libs4go/ethers v0.0.0-20210830141338-f7af7197479f
	github.com/libs4go/scf4go v0.0.7
	github.com/libs4go/smf4go v0.0.9
)

require (
	github.com/bitly/go-simplejson v0.5.0 // indirect
	github.com/google/uuid v1.0.0 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/libs4go/sdi4go v0.0.6 // indirect
	github.com/libs4go/slf4go v0.0.4 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
)

replace github.com/libs4go/ethers => ../ethers
