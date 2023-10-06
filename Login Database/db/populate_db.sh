#!/bin/sh
DB_SCRIPT_LOCATION="/tmp/psql_data/Users_Table.sql"
echo "*** CREATING DATABASE ***"
psql -U postgres < "$DB_SCRIPT_LOCATION";
