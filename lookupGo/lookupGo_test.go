package lookupGo

import (
	"regexp"
	"testing"
)

func TestParseInput(t *testing.T) {
	testInputArr := []string{
		"0.0:0.0", // InValid
		"70cd7d4771dae80f3450ffe13afebcf8ddadf0e63465db9896316d4db44df06512", // Invalid
		"256.255.0.0", // Invalid
		"916ddaa5b9a27823b7f41b184ac3dc58", // Valid but no results
	}

	expectedOutliers := []string{
		"0.0:0.0 is Invalid IP address. 0.0:0.0 is neither IPv4 nor IPv6\n0.0:0.0 is Unknown domain\n0.0:0.0 is InValid Hash. Its not strictly Alphanumeric string",
		"70cd7d4771dae80f3450ffe13afebcf8ddadf0e63465db9896316d4db44df06512 is InValid Hash. Alphanumeric string Length :66",
		"256.255.0.0 is Invalid IP address. 256.255.0.0 is neither IPv4 nor IPv6\n256.255.0.0 is Unknown domain\n256.255.0.0 is InValid Hash. Its not strictly Alphanumeric string",
		"916ddaa5b9a27823b7f41b184ac3dc58 is Valid Hash. Its type md5 hash\nNo hashes found in https://hashtoolkit.com/decrypt-hash/?hash=916ddaa5b9a27823b7f41b184ac3dc58",
	}

	for i := range testInputArr {
		gotOutlier := ParseInput(testInputArr[i])

		remove := regexp.MustCompile(`\r?\n`)
		if remove.ReplaceAllString(gotOutlier, "") != remove.ReplaceAllString(expectedOutliers[i], "") {
			t.Errorf("gotOutlier %s expectedOutliers %s", gotOutlier, expectedOutliers[i])
		}
	}
}