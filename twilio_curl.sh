#!/bin/bash
# small cli to test environment configuration is correct
message=${1:-"Hello from dev environment"}
curl "https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Messages.json" -X POST \
--data-urlencode "To=$YOUR_PHONE_NUMBER" \
--data-urlencode "From=$TWILIO_PHONE_NUMBER" \
--data-urlencode "Body=$message" \
-u $TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN
