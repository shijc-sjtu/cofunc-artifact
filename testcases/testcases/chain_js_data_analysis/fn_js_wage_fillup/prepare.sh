#!/bin/bash -e

SCRIPTS_DIR=$(pwd)

COUCHDB_IP=localhost
COUCHDB_PORT=5984
COUCHDB_USERNAME=admin
COUCHDB_PASSWORD=password

WAGE_COUCHDB_DATABASE="wage"
WAGE_COUCHDB_DATABASE_STATISTICS="wage-statistics"

record_num=1000
couchdb_url=http://$COUCHDB_USERNAME:$COUCHDB_PASSWORD@$COUCHDB_IP:$COUCHDB_PORT

echo "Re-creating databases"
curl -X DELETE $couchdb_url/$WAGE_COUCHDB_DATABASE
curl -X DELETE $couchdb_url/$WAGE_COUCHDB_DATABASE_STATISTICS
curl -X PUT $couchdb_url/$WAGE_COUCHDB_DATABASE
curl -X PUT $couchdb_url/$WAGE_COUCHDB_DATABASE_STATISTICS

if [ ! -f $SCRIPTS_DIR/records.json ]; then
    echo "Creating initial records to post to couchdb..."
    $SCRIPTS_DIR/records_generator.sh $record_num
fi

curl -H 'Content-Type: application/json' \
    -X POST $couchdb_url/$WAGE_COUCHDB_DATABASE/_bulk_docs \
    --data "@$SCRIPTS_DIR/records.json"
