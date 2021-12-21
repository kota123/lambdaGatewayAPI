# lambdaGatewayAPI
Lambda microservice triggered by API Gateway to lookup ip address, domain or hash (md5, sha1, sha256)

## How to deploy

- Build the lambdaGatewayAPI.go file

`$ GOOS=linux go build /f/Skills/Go/lambdaGatewayAPI/lambdaGatewayAPI.go`

- Zip the build into function.zip file

`zip function.zip lambdaGatewayAPI`

Upload the function.zip in Lambda Code.
