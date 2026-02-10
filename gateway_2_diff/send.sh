#!/bin/bash

USERNAME='user1'
PASSWORD='user1'
BROKER='localhost'
PORT=2883
TOPIC_FAMILY='meshlora/data/'

if [ "$#" -ne 3 ]; then
	echo "Usage: $0 <topic> <dst MeshLora addr> <message>"
	exit 1
fi

echo "sending mosquitto msg"
mosquitto_pub -u $USERNAME -P $PASSWORD -h $BROKER -p $PORT -t "${TOPIC_FAMILY}${1}" \
	-m "{'dst': ${2}, 'content': '${3}'}"
echo "mosquitto msg sent"
