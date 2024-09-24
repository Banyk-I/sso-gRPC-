Project created no to release only for see like working gRPC


#RUN MAIN
go run ./cmd/sso/main.go --config=./config/local.yaml

#Migration
go run ./cmd/migrator --storage-path=./storage/sso.db --migrations-path=./migrations
#OR
task migrate

#Test migrations
go run ./cmd/migrator/main.go --storage-path=./storage/sso.db --migrations-path=./tests/migrations --migrations-table=migrations_test

# sso-gRPC-
