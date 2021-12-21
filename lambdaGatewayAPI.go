package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"lambdaGatewayAPI/lookupGo"
	"strings"
)

func main() {
	lambda.Start(HandleRequest)
}

func HandleRequest(ctx context.Context, lookupRequest events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	fmt.Printf("Processing request data for request %s.\n", lookupRequest.RequestContext.RequestID)
	fmt.Printf("lookupRequest = %v.\n", lookupRequest)

	fmt.Println("QueryStringParameters:")
	for key, value := range lookupRequest.QueryStringParameters {
		fmt.Printf("%s: %s\n", key, value)
	}

	httpMethod := strings.Split(lookupRequest.RouteKey, " ")[0]
	fmt.Println("httpMethod: " + httpMethod)

	// Initialize event APIGatewayProxyResponse
	lookUpResponse := events.APIGatewayV2HTTPResponse{Headers: lookupRequest.Headers}

	// Check httpMethod and invoke lookupGo.ParseInput
	if httpMethod == "GET" {
		if len(lookupRequest.QueryStringParameters) > 0 && lookupRequest.QueryStringParameters["lookUp"] != "" {
			parsedOutput := lookupGo.ParseInput(lookupRequest.QueryStringParameters["lookUp"])
			fmt.Println("lookUpResponse: " + parsedOutput)
			// Return parsedOutput
			lookUpResponse.StatusCode = 200
			lookUpResponse.Body = parsedOutput
		} else {
			// Return Empty QueryStringParameters
			lookUpResponse.StatusCode = 400
			lookUpResponse.Body = `Empty QueryStringParameters`
		}
	} else {
		// Return Unsupported Method
		lookUpResponse.StatusCode = 400
		lookUpResponse.Body = `Unsupported Method ` + httpMethod
	}
	// Return lookUpResponse
	return lookUpResponse, nil
}