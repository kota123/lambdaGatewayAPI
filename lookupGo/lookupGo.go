package lookupGo

import (
	"fmt"
	"github.com/likexian/whois"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
)

// ParseInput func to parse the input
func ParseInput(input string) string {
	if input != "" { // If input is non-empty

		// Initialize response string
		var parsedOutput string

		// Parse the IP Address
		isParsed, parseIPAddressOutput := ParseIPAddress(input)
		// Append the parsed output to response
		parsedOutput += parseIPAddressOutput

		// If IP Address Parse failed
		if !isParsed {
			//Parse the Domain
			isParsed, parsedOutput = ParseDomain(input, parsedOutput)
		}

		// If IP Address/Domain Parse Succeeded
		if isParsed {

			// Lookup WhoIs the Parsed IP Address Or Domain
			parsedOutput += WhoIsLookup(input)

		} else { // If IP Address/Domain Parse Failed

			// Parse the Hash
			isParsed, parsedOutput, _ = ParseHash(input, parsedOutput)

			// If Hash Parse Succeeded
			if isParsed {
				// Search HashToolKitData
				parsedOutput += SearchHashToolKitData(input)
			}

		}

		// Return the parsedOutput
		return parsedOutput
		//fmt.Printf("%s", parsedOutput)

	}
	return "Empty input. Pls provide IP Address, Domain Or Hash(md5, sha1, sha256)"
}

// WhoIsLookup func uses the whois package
func WhoIsLookup(str string) string {
	formatString := "WhoIsLookup result for " + str + " = %s\n"
	result, err := whois.Whois(str)
	if err == nil {
		return fmt.Sprintf(formatString, result)
	}
	return fmt.Sprintf(formatString, err.Error())
}

// ParseIPAddress func uses the net package
func ParseIPAddress(ip string) (bool, string) {
	ipAddress := net.ParseIP(ip)
	if ipAddress == nil {
		return false, fmt.Sprintf("%s is Invalid IP address. %s is neither IPv4 nor IPv6\n", ip, ip)
	} else {
		semicolonPattern := ":"
		isIPv6, matchPatternError := regexp.MatchString(semicolonPattern, ip)
		if matchPatternError == nil {
			ipFormat := "IPv6"
			responseString := ip + " is Valid address. %s is an %s address\n"
			if !isIPv6 {
				ipFormat = "IPv4"
			}
			return true, fmt.Sprintf(responseString, ipAddress, ipFormat)
		}
		return false, fmt.Sprintf(ip +" is InValid IP address. Encountered matchPatternError :%s\n", matchPatternError.Error())
	}
}

// ParseDomain func uses the net package
func ParseDomain(domain string, parsedOutput string) (bool, string) {
	addr,err := net.LookupIP(domain)
	if err != nil {
		return false, fmt.Sprintf("%s%s is Unknown domain\n", parsedOutput, domain)
	} else {
		return true, fmt.Sprintf("%s is Valid domain with IP : %v\n", domain, addr)
	}
}

// ParseHash func identifies the hash using the strictly alphanumeric length
func ParseHash(hash string, parsedOutput string) (bool, string, string)  {

	alphaNumericPattern := "^[a-fA-F0-9]+$" // Strictly Alpha-Numeric from start till end
	isHash, matchPatternError := regexp.MatchString(alphaNumericPattern, hash)
	if matchPatternError == nil {
		hashType := "md5"
		responseString := "%s is Valid Hash. Its type %s hash\n"
		hashLength := len(hash)
		if isHash {
			parsedOutput = "" // Re-initialize response
			if hashLength == 32 { // md5 is of 32 length alphanumeric
				return true, fmt.Sprintf(responseString, hash, hashType), hashType
			} else if hashLength == 40 { // sha1 is of 32 length alphanumeric
				hashType = "sha1"
				return true, fmt.Sprintf(responseString, hash, hashType), hashType
			} else if hashLength == 64 { // sha1 is of 32 length alphanumeric
				hashType = "sha256"
				return true, fmt.Sprintf(responseString, hash, hashType), hashType
			}
			return false, fmt.Sprintf("%s%s is InValid Hash. Alphanumeric string Length :%d\n", parsedOutput, hash, hashLength), ""

		}
		return false, fmt.Sprintf("%s%s is InValid Hash. Its not strictly Alphanumeric string\n", parsedOutput, hash), ""

	}
	return false, fmt.Sprintf("%s%s is InValid Hash. Encountered matchPatternError :%s\n", parsedOutput, hash, matchPatternError.Error()), ""

}

// SearchHashToolKitData func searches the hashtoolkit.com's hash data
func SearchHashToolKitData(hash string) string {

	// Search the hash in hashtoolkit.com's hash data
	hashToolKitUrl := "https://hashtoolkit.com/decrypt-hash/?hash="
	//fmt.Println("Endpoint = ", hash)
	// Get Response
	resp, err := http.Get(hashToolKitUrl + hash)
	if err != nil { // Handle Get Error
		return "Fatal SearchHashToolKitData Error : " + err.Error()
	}
	// Defer closing body
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	// Read resp.Body as []bytes
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	// Convert response body to string
	bodyString := string(bodyBytes)

	//fmt.Println("Response = ", bodyString)

	// Regex to Compile hashes found
	foundHashesRegExp := regexp.MustCompile(`Hashes for: <code>.+</code>?`)
	// Regex to Compile hashes Not found
	notFoundHashesRegExp := regexp.MustCompile(`No hashes found for <code>.+</code>?`)
	// Find string if found hashes
	foundHashes := foundHashesRegExp.FindString(bodyString) // E.g.: "Hashes for: <code>apple.com</code>", ""
	// Find string if Not found hashes
	notFoundHashes := notFoundHashesRegExp.FindString(bodyString) // E.g.: "", "No hashes found for <code>916ddaa5b9a27823b7f41b184ac3dc58</code>"
	// Code Tag Start
	startCodeTag := regexp.MustCompile(`<code>?`)
	// Code Tag End
	endCodeTag := regexp.MustCompile(`</code>?`)

	if foundHashes != "" { // If hashes found

		// Of the found hash, Find the start string index
		startCodeTagIndex := startCodeTag.FindStringIndex(foundHashes)
		// Of the found hash, Find the end string index
		endCodeTagIndex := endCodeTag.FindStringIndex(foundHashes)

		// Lookup WhoIs the found hash
		return WhoIsLookup(foundHashes[startCodeTagIndex[1]:endCodeTagIndex[0]])

	} else if notFoundHashes != "" { // If hashes Not found
		return fmt.Sprintf("No hashes found in %s%s\n", hashToolKitUrl, hash)
	}

	// Return nothing
	return ""
}