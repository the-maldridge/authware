module github.com/the-maldridge/authware/demo/basic

go 1.24.4

replace github.com/the-maldridge/authware => ../../

require (
	github.com/GehirnInc/crypt v0.0.0-20230320061759-8cc1b52080c5 // indirect
	github.com/go-chi/chi/v5 v5.2.2 // indirect
	github.com/tg123/go-htpasswd v1.2.4 // indirect
	golang.org/x/crypto v0.37.0 // indirect
)

require github.com/the-maldridge/authware v0.0.0
