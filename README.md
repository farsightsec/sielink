# Sielink protocol library

Package `sielink` implements the protocol used for communication between
SIE sensors and submission servers, as well for coordination between
submission servers.

It contains two subdirectories:

 * `rawlink`, the core implementation of the Sielink 'Link' protocol, and
 * `client`, a profile of the Sielink protocol suitable for a sensor.

 The `client` library supports both publication and subscription through
 the Sielink protocol.

## Requirements

`sielink` relies on the following two go libraries:

 * github.com/golang/protobuf/proto
 * golang.org/x/net/websocket

## Client Usage

First, set up a new client with:

        import "github.com/farsightsec/sielink/client"

        cli := client.NewClient(&client.Config{
                Heartbeat: time.Minute,
                // The URL is required, and must be a valid URL,
                // but is otherwise unused by sielink.
                URL:       "https://localhost/my-submit-app",
                APIKey:    apiKeyString,
        })

then open one or more connections to submission servers with:

        err := cli.DialAndHandle("wss://<server>/session/<sessionName>")

`DialAndHandle` only returns when the connection closes, so this should be run
in a retry loop on a separate goroutine.

### Submitting data

Data submitted to the submission service must be enclosed in a `*sielink.Payload`,
and tagged with a data type (sielink only supports NMSG container data as of
this writing) and channel.

        import (
                "github.com/golang/protobuf/proto"
                "github.com/farsightsec/sielink"
        )

        err := cli.Send(&sielink.Payload{
                Channel: proto.Uint32(channelNumber),
                PayloadType: sielink.PayloadType_NmsgContainer.Enum(),
                Data: data, // []byte, serialized NMSG container
        })

### Subscribing to data

The `sielink/client` package also allows subscribing to data, with:

        cli.Subscribe(channel1, channel2, ...)

        for p := range cli.Receive() {
                if p.PayloadType != sielink.PayloadType_NmsgContainer {
                        continue
                }
                processNmsgContainer(p.GetData())
        }
