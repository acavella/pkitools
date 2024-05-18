package main

import (
	"fmt"

	"github.com/spf13/viper"

	log "github.com/sirupsen/logrus"
)

var appVersion = "0.0.0"
var appBuild = "UNK"
var appBuildDate = "00000000-0000"

func init() {
	log.SetFormatter(&log.TextFormatter{
		QuoteEmptyFields: true,
		FullTimestamp:    true,
	})

	viper.SetConfigName("config")  // name of config file (without extension)
	viper.SetConfigType("yaml")    // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("./conf/") // optionally look for config in the working directory

	err2 := viper.ReadInConfig() // Find and read the config file
	if err2 != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err2.Error()))
	}

	printver()

}

func main() {

	// Sets CA ID and URI to string arrays
	commonName := viper.GetString("dn.cn")
	keyUsage := viper.GetStringSlice("ku")

	fmt.Printf("CN: %s\n", commonName)

	for i := 0; i < len(keyUsage); i++ {

		fmt.Printf("KU: %s\n", keyUsage[i])

	}

}

func printver() {
	fmt.Printf("GoRevoke ver. %s\n", appVersion)
	fmt.Printf("Build Type: %s\n", appBuild)
	fmt.Printf("Build Date: %s\n", appBuildDate)
}
