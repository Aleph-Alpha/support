#!/usr/bin/env bash

set -oue pipefail
QDRANT_COLLECTIONS_FILE="collections"
QDRANT_SNAPSHOTS_FILE="snapshots"
QDRANT_FAILED_RECOVERY_FILE="failed_snapshot_recovery"
QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE="snapshot_recovery_history"
QDRANT_ALIAS_RECOVERY_HISTORY_FILE="alias_recovery_history"
QDRANT_COLLECTION_ALIASES="collection_aliases"
QDRANT_WAIT_ON_TASK=${QDRANT_WAIT_ON_TASK:-true}
CURL_TIMEOUT="${CURL_TIMEOUT:-1800}"
QDRANT_S3_ALIAS="qdrant_s3_snaphost"
QDRANT_S3_LINK_EXPIRY_DURATION="${QDRANT_S3_LINK_EXPIRY_DURATION:-3600s}"

declare -a peer_uri_map;
# printf wrapper helper
_printf() {
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  printf '[%s] ' "$ts"
  printf "$@"
}

# curl wrapper helper
_curl() {
  local method="${1:-GET}"
  shift 1
  local url="$1"
  shift 1

  # Capture both response body and HTTP status code
  local response
  response=$(curl -sSf -w "\n%{http_code}" \
    --max-time "${CURL_TIMEOUT}" \
    --connect-timeout 30 \
    -X "${method}" \
    "$@" \
    "${url}")

  # Extract HTTP code (last line) and body (everything else)
  local http_code
  http_code=$(echo "${response}" | tail -n1)
  local result
  result=$(echo "${response}" | sed '$d')

  # Check if HTTP code indicates success (2xx)
  if [[ "${http_code}" =~ ^2[0-9]{2}$ ]]; then
      echo "${result}"
      return 0
  fi

  # Return the result even on failure (caller may want to inspect it)
  echo "${result}"
  return 1
}

# Extracts the source and restore hosts from the QDRANT_SOURCE_HOSTS and QDRANT_RESTORE_HOSTS variables
get_hosts() {
  IFS=',' read -ra source_hosts <<< "$QDRANT_SOURCE_HOSTS"
  IFS=',' read -ra restore_hosts <<< "$QDRANT_RESTORE_HOSTS"
}

# Gets all collections from a qdrant node and stores it in $QDRANT_COLLECTIONS_FILE
get_collections() {
  local status=""
  local result=""
  if [[ -s "$QDRANT_COLLECTIONS_FILE" ]]; then
      _printf "collection already fetched! ... need a fresh one? clear %s file\n" "$QDRANT_COLLECTIONS_FILE"
      return
  fi
  _printf "fetching collections!\n"

  local host="${source_hosts[0]}"

  collections_count=0

  result=$(_curl GET "$host/collections" --header "api-key: $QDRANT_API_KEY")

  status=$(jq -r '.status' <<< "$result")
  if [ "$status" != "ok" ]; then
      _printf "[%s] failed to get collections, got this instead %s\n" "$host" "${result//[[:space:]]/}"
      exit 1
  fi

  track_collection "$host" "$result"

  _printf "%s file updated, found %d collection(s)!\n" "$QDRANT_COLLECTIONS_FILE" "$collections_count"

  collections_count=0
}

# appends collection from a qdrant node to $QDRANT_COLLECTIONS_FILE
track_collection(){
  local host="$1"
  local result="$2"
  _result=$(jq -c '.result.collections // [] | .[]' <<< "$result")

  while read -r item; do
    local collection_name=""
    collection_name=$(jq -r '.name' <<< "$item")
    ((collections_count=collections_count+1))
    printf '%s,%s\n' "$host" "$collection_name" >> $QDRANT_COLLECTIONS_FILE
  done <<< "$_result"
}

create_snapshot_from_peer() {
  local host="$1"
  local collection_name="$2"
  local result=""
  result=$(_curl POST "$host/collections/$collection_name/snapshots?wait=$QDRANT_WAIT_ON_TASK" --header "api-key: $QDRANT_API_KEY")

  status=$(jq -r '.status' <<< "$result")
  snapshot_name=$(jq -r '.result.name // "unknown"' <<< "$result")

  if [ "$status" = "ok" ]; then
    ((success_snapshot_count=success_snapshot_count+1))
    _printf '[%s] Snapshot %s for %s collection created successfully\n' "$host" "$snapshot_name" "$collection_name"
  elif [ "$status" = "accepted" ]; then
    ((success_snapshot_count=success_snapshot_count+1))
    _printf '[%s] Snapshot %s for %s collection accepted successfully\n' "$host" "$snapshot_name" "$collection_name"
  else
    ((failed_snapshot_count=failed_snapshot_count+1))
    _printf '[%s] Snapshot %s for %s collection failed with %s\n' "$host" "$snapshot_name" "$collection_name" "${result//[[:space:]]/}"
  fi

  printf '%s,%s,%s\n' "$host" "$collection_name" "$snapshot_name" >> $QDRANT_SNAPSHOTS_FILE
}

# creates and appends created collection snapshot from a qdrant node to $QDRANT_SNAPSHOTS_FILE
track_created_collection_snapshot() {
    local host="${source_hosts[0]}"
    local collection_name="$1"
    local result=""
    local status=""
    local snapshot_name=""
    local collection_details_result=""
    local local_shards_length=0
    local remote_shards_length=0
    local remote_shards_result=""


    _printf '[%s] creating snapshot for %s collection\n' "$host" "$collection_name"

    collection_details_result=$(_curl GET "$host/collections/$collection_name" --header "api-key: $QDRANT_API_KEY")
    status=$(jq -r '.result?.status' <<< "$collection_details_result")

    if [ "$status" != "green" ]; then
      _printf '[%s] snapshot for %s collection will be created with %s status review https://qdrant.tech/documentation/concepts/collections/#collection-info.\n' "$host" "$collection_name" "$status"
    fi

    if [ "$GET_PEERS_FROM_CLUSTER_INFO" = "true" ]; then
      local peer_id=0
      local peer_url=""
      cluster_result=$(_curl GET "$host/collections/$collection_name/cluster" --header "api-key: $QDRANT_API_KEY")

      local_shards_length=$(jq -c '(.result.local_shards // []) | length' <<< "$cluster_result")

      peer_id=$(jq -r '.result.peer_id // "unknown"' <<< "$cluster_result")

      if [ "$peer_id" = "unknown" ]; then
        peer_url="$host"
      else
        peer_url=${peer_uri_map[$peer_id]}
      fi

      if [ "$local_shards_length" -gt 0 ]; then
        _printf "[%s] found %d local shard(s) for %s collection on peer, will create a snapshot.\n" "$peer_url" "$local_shards_length" "$collection_name"
        create_snapshot_from_peer "$peer_url" "$collection_name"
      else
        _printf "[%s] could not find local shard(s) for %s collection on peer.\n" "$peer_url" "$collection_name"
      fi

      remote_shards_length=$(jq -c '(.result.remote_shards // []) | length' <<< "$cluster_result")

      remote_shards_result=$(jq -c '.result.remote_shards // [] | .[]' <<< "$cluster_result")

      if [ "$remote_shards_length" -gt 0 ]; then
        _printf "[%s] found %d remote shard(s) for %s collection on peer, will create a snapshot.\n" "$peer_url" "$remote_shards_length" "$collection_name"
        while read -r item; do
          peer_id=$(jq -r '.peer_id' <<< "$item")
          peer_url=${peer_uri_map[$peer_id]}
          create_snapshot_from_peer "$peer_url" "$collection_name"
        done <<< "$remote_shards_result"
      else
        _printf "[%s] could not find remote shard(s) for %s collection on peer.\n" "$peer_url" "$collection_name"
      fi
    else

      for _host in "${source_hosts[@]}"; do
        create_snapshot_from_peer "$_host" "$collection_name"
      done

    fi

}

# creates and appends created collection snapshots from qdrant node peers to $QDRANT_SNAPSHOTS_FILE
create_collection_snapshot() {
  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
      get_collections
  fi

  if [ ! -f $QDRANT_COLLECTIONS_FILE ]; then
    _printf "non error exit since file does not %s exist.\n" "$QDRANT_COLLECTIONS_FILE"
    exit 0
  fi

  success_snapshot_count=0
  failed_snapshot_count=0

  while IFS= read -r line; do
    IFS=',' read -ra cols <<< "$line"
    local collection_name="${cols[1]}"
    track_created_collection_snapshot "$collection_name"
  done < $QDRANT_COLLECTIONS_FILE

  _printf "snapshot creation summary: %d created, %d failed!\n" "$success_snapshot_count" "$failed_snapshot_count"

  failed_snapshot_count=0
  success_snapshot_count=0
}

# gets the latest collection snapshot from a qdrant node and appends it to $QDRANT_SNAPSHOTS_FILE
fetch_collection_snapshot() {
  local host="$1"
  local collection_name="$2"
  local result=""
  local datetime="$3"

  if [ "$datetime" = "" ]; then
    _printf "[%s] fetching snapshots for %s collection.\n" "$host" "$collection_name"
  else
    _printf "[%s] fetching snapshots for %s collection for date: %s .\n" "$host" "$collection_name" "$datetime"
  fi

  result=$(_curl GET \
          "$host/collections/$collection_name/snapshots" \
          --header "api-key: $QDRANT_API_KEY")
  status=$(jq -r '.status?' <<< "$result")
  if [ "$status" != "ok" ]; then
      _printf "[%s] failed to fetch snapshots for collections %s, got this instead %s\n" "$host" "$collection_name" "${result//[[:space:]]/}"
      return
  fi

  resultLength=$(jq -c '(.result // []) | length' <<< "$result")

  if [ "$resultLength" -eq 0 ]; then
      _printf "[%s] could not find snapshots for collections %s, got this instead %s\n" "$host" "$collection_name" "${result//[[:space:]]/}"
      return
  fi

  item=$(jq -c '.result[0] // empty' <<< "$result")

  _result=$(jq -c '.result // [] | .[]' <<< "$result")
  while read -r item; do
    local snapshot_name=""
    snapshot_name=$(jq -r '.name' <<< "$item")

    if [[ -n "$datetime" && "$snapshot_name" != *"$datetime"* ]]; then
      continue
    fi

    ((snapshot_count=snapshot_count+1))

    printf '%s,%s,%s\n' "$host" "$collection_name" "$snapshot_name" >> $QDRANT_SNAPSHOTS_FILE
  done <<< "$_result"

  if [ "$snapshot_count" -gt 0 ]; then
    _printf "[%s] completed fetching snapshots for %s collection!\n" "$host" "$collection_name"
  else
    _printf "[%s] no snapshots matching date: %s for %s collection!\n" "$host" "$datetime" "$collection_name"
  fi

}

# gets the latest collection snapshot from a qdrant node and appends it to $QDRANT_SNAPSHOTS_FILE
fetch_collection_snapshot_from_s3() {
  local host="$1"
  local collection_name="$2"
  local result=""
  local datetime="$3"

  if [ "$datetime" = "" ]; then
    _printf "[%s] fetching snapshots for %s collection.\n" "$host" "$collection_name"
  else
    _printf "[%s] fetching snapshots for %s collection for date: %s.\n" "$host" "$collection_name" "$datetime"
  fi

  local key="$QDRANT_S3_BUCKET_NAME/snapshots/$collection_name"

  local result=""
  result=$(mc ls -r --json "$QDRANT_S3_ALIAS/$key")

  if [ "$result" = "" ]; then
     _printf "[%s] snapshots for %s collection not found in s3 path: %s ...skipping!\n" "$host" "$collection_name" "$key"
     return
  fi

  _result=$(jq -c '.' <<< "$result")

  while read -r item; do
    local status=""
    status=$(jq -r '.status?' <<< "$item")
    if [ "$status" != "success" ]; then
        _printf "[%s] failed to fetch snapshots for collections %s, got this instead %s\n" "$host" "$collection_name" "${result//[[:space:]]/}"
        continue
    fi

    local snapshot_name=""
    snapshot_name=$(jq -r '.key' <<< "$item")

    if [[ -n "$datetime" && "$snapshot_name" != *"$datetime"* ]]; then
      continue
    fi

    ((snapshot_count=snapshot_count+1))

    printf '%s,%s,%s\n' "$host" "$collection_name" "$snapshot_name" >> $QDRANT_SNAPSHOTS_FILE
  done <<< "$_result"

  if [ "$snapshot_count" -gt 0 ]; then
    _printf "[%s] completed fetching snapshots for %s collection!\n" "$host" "$collection_name"
  else
    _printf "[%s] no snapshots matching date: %s for %s collection!\n" "$host" "$datetime" "$collection_name"
  fi
}

# generates a list of collection snapshots from a s3 and appends it to $QDRANT_SNAPSHOTS_FILE
generate_snapshot_file_from_s3() {
  local datetime="${1:-}"
  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
      get_collections
  fi

  snapshot_count=0

  while IFS= read -r line; do
    IFS=',' read -ra cols <<< "$line"
    local host="${cols[0]}"
    local collection_name="${cols[1]}"
    fetch_collection_snapshot_from_s3 "$host" "$collection_name" "$datetime"
  done < $QDRANT_COLLECTIONS_FILE

  _printf "%s file updated, found %d snapshots!\n" "$QDRANT_SNAPSHOTS_FILE" "$snapshot_count"

  snapshot_count=0
}

# generates a list of collection snapshots from a qdrant node and appends it to $QDRANT_SNAPSHOTS_FILE
generate_snapshot_file_from_instance() {
  local datetime="${1:-}"

  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
      get_collections
  fi

  if [[ -s "$QDRANT_SNAPSHOTS_FILE" ]]; then
      _printf "snapshots already fetched! ... need a fresh one? clear %s file\n" "$QDRANT_SNAPSHOTS_FILE"
      return
  fi

  if [ ! -f $QDRANT_COLLECTIONS_FILE ]; then
    _printf "non error exit since file does not %s exist.\n" "$QDRANT_COLLECTIONS_FILE"
    exit 0
  fi

  snapshot_count=0

  while IFS= read -r line; do
    IFS=',' read -ra cols <<< "$line"
    local host="${cols[0]}"
    local collection_name="${cols[1]}"
    fetch_collection_snapshot "$host" "$collection_name" "$datetime"
  done < $QDRANT_COLLECTIONS_FILE

  _printf "%s file updated, found %d snapshot(s)!\n" "$QDRANT_SNAPSHOTS_FILE" "$snapshot_count"

  snapshot_count=0
}

# generates an s3 presigned url for collection snapshot recovery
get_s3_url() {
  local collection_name="$1"
  local snapshot_name="$2"
  local key="snapshots/$collection_name/$snapshot_name"

  local result=""
  if result=$(mc share download --expire "$QDRANT_S3_LINK_EXPIRY_DURATION" --json "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$key"); then
      _printf "succesfully obtained presigned s3 url for %s\n" "$key"
  fi

  local status=""
  status=$(jq -r '.status?' <<< "$result")
  if [ "$status" != "success" ]; then
      _printf "[%s] failed to fetch snapshots for collections %s, got this instead %s\n" "$host" "$collection_name" "${result//[[:space:]]/}"
  fi

  s3_presigned_url=$(jq -r '.share' <<< "$result")
}

# restores an collection snapshot from an s3 url updates the $QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE and $QDRANT_FAILED_RECOVERY_FILE
recover_collection_snapshot() {
    local host="$1"
    local collection_name="$2"
    local snapshot_name="$3"
    local result=""
    local status=""

    _printf "[%s] started to recover %s snapshot of %s collection...\n" "$host" "$snapshot_name" "$collection_name"

    get_s3_url "$collection_name" "$snapshot_name"

    result=$(_curl PUT \
               "$host/collections/$collection_name/snapshots/recover?wait=$QDRANT_WAIT_ON_TASK" \
               --header "api-key: $QDRANT_API_KEY" \
               --header "Content-Type: application/json" \
               --data "{ \"location\": \"$s3_presigned_url\", \"priority\": \"snapshot\" }")

    status=$(jq -r '.status' <<< "$result")

    if [ "$status" = "ok" ]; then
      ((recovered_count=recovered_count+1))
      _printf "[%s] successfully recovered %s snapshot of %s collection\n" "$host" "$snapshot_name" "$collection_name"
      printf '%s,%s,%s\n' "$host" "$snapshot_name" "$status" >> $QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE
    elif [ "$status" = "accepted" ]; then
      _printf "[%s] successfully accepted recovery of snapshot %s for %s collection\n" "$host" "$snapshot_name" "$collection_name"
    else
      ((fail_recovered_count=fail_recovered_count+1))
      _printf "[%s] failed to recover %s snapshot of %s collection, got this %s instead\n" "$host" "$snapshot_name" "$collection_name" "${result//[[:space:]]/}"
      printf '%s,%s,%s\n' "$host" "$snapshot_name" "$status" >> $QDRANT_FAILED_RECOVERY_FILE
    fi
}

# restores an collection snapshots from an s3 url, reads $QDRANT_SNAPSHOTS_FILE for the fetched snapshots
recover_collection_snapshots(){
  local datetime="${1:-}"


  if [[ ! -s  $QDRANT_SNAPSHOTS_FILE ]]; then
    generate_snapshot_file_from_s3 "$datetime"
  fi

  touch "$QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE"

  snapshot_count=$(wc -l < $QDRANT_SNAPSHOTS_FILE)

  recovered_count=0
  fail_recovered_count=0
  while IFS= read -r line; do
    IFS=',' read -ra cols <<< "$line"

    for host in "${restore_hosts[@]}"; do
      local collection_name="${cols[1]}"
      local snapshot_name="${cols[2]}"

      history_count=$(grep -cw "$snapshot_name,ok" "$QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE" || true)

      if [ "$history_count" -gt 0 ]; then
        ((recovered_count=recovered_count+1))
        _printf "[%s] snapshot %s already recovered, skipping!\n" "$host" "$snapshot_name"
        continue
      fi
      recover_collection_snapshot "$host" "$collection_name" "$snapshot_name"
    done
  done < $QDRANT_SNAPSHOTS_FILE

  _printf "recovery summary: %d/%d snapshots recovered, %d failed.\n" "$recovered_count" "$snapshot_count" "$fail_recovered_count"
  recovered_count=0
  fail_recovered_count=0
  snapshot_count=0
}

# gets the collection aliases from a qdrant node and appends it to $QDRANT_COLLECTION_ALIASES file
get_collection_aliases() {
  local host="${source_hosts[0]}"
  local result=""
  local status=""

  _printf "[%s] fetching collection aliases...\n" "$host"

  result=$(_curl GET \
             "$host/aliases" \
             --header "api-key: $QDRANT_API_KEY")

  status=$(jq -r '.status' <<< "$result")

  if [ "$status" != "ok" ]; then
      _printf "[%s] failed to fetch collection aliases, got this instead %s\n" "$host" "${result//[[:space:]]/}"
      exit 1
  fi

  local colla_length=0
  colla_length=$(jq -c '(.result.aliases // []) | length' <<< "$result")

  if [ "$colla_length" -gt 0 ]; then
    _result=$(jq -c '.result.aliases // [] | .[]' <<< "$result")
    while read -r item; do
      local collection_name=""
      local alias_name=""
      collection_name=$(jq -r '.collection_name' <<< "$item")
      alias_name=$(jq -r '.alias_name' <<< "$item")
      printf '%s,%s\n' "$collection_name" "$alias_name" >> $QDRANT_COLLECTION_ALIASES
    done <<< "$_result"
  fi

  _printf "%s file updated,found %d collection alias(es)!\n" "$QDRANT_COLLECTION_ALIASES" "$colla_length"
}

# restores collection alias to a qdrant node and appends progress to $QDRANT_ALIAS_RECOVERY_HISTORY_FILE
recover_collection_alias() {
  local host="${source_hosts[0]}"
  local collection_name="$1"
  local alias_name="$2"
  local status=""
  local result=""

  result=$(_curl POST \
             "$host/collections/aliases" \
             --header "api-key: $QDRANT_API_KEY" \
             --header "Content-Type: application/json" \
             --data-raw "{
               \"actions\": [
                 {
                   \"create_alias\": {
                     \"collection_name\": \"$collection_name\",
                     \"alias_name\": \"$alias_name\"
                   }
                 }
               ]
             }")

  status=$(jq -r '.status' <<< "$result")

  if [ "$status" != "ok" ]; then
    ((failed_recovered_colla_count=failed_recovered_colla_count+1))
    _printf "[%s] failed to fetch collection alias %s:%s, got this instead %s\n" "$host" "$collection_name" "$alias_name" "${result//[[:space:]]/}"
    return
  fi

  ((recovered_colla_count=recovered_colla_count+1))
  printf '%s,%s,%s\n' "$collection_name" "$alias_name" "$status" >> $QDRANT_ALIAS_RECOVERY_HISTORY_FILE
}

# restores collection aliases to a qdrant node and appends progress to $QDRANT_ALIAS_RECOVERY_HISTORY_FILE
recover_collection_aliases() {
  if [[ ! -s "$QDRANT_COLLECTION_ALIASES" ]]; then
      get_collection_aliases
  fi

  if [ ! -f "$QDRANT_COLLECTION_ALIASES" ]; then
      _printf "[%s] collection aliases do not exist on source!\n" "$host"
      return
  fi

  colla_count=$(wc -l < $QDRANT_COLLECTION_ALIASES)
  recovered_colla_count=0
  failed_recovered_colla_count=0

  local host="${restore_hosts[0]}"

  touch $QDRANT_ALIAS_RECOVERY_HISTORY_FILE


  while IFS= read -r line; do
    IFS=',' read -ra cols <<< "$line"
    local collection_name="${cols[0]}"
    local alias_name="${cols[1]}"

    history_count=$(grep -cw "$collection_name,$alias_name,ok" "$QDRANT_ALIAS_RECOVERY_HISTORY_FILE" || true)

    if [ "$history_count" -gt 0 ]; then
      _printf "[%s] collection alias %s:%s already recovered, skipping!\n" "$host" "$collection_name" "$alias_name"
      continue
    fi
    recover_collection_alias "$collection_name" "$alias_name"
  done < $QDRANT_COLLECTION_ALIASES

  _printf "recovery summary: %d/%d collection aliases recovered, %d failed.\n" "$recovered_colla_count" "$colla_count" "$failed_recovered_colla_count"

  colla_count=0
  recovered_colla_count=0
  failed_recovered_colla_count=0
}

# removes state files with(out) backup
delete_files() {
  local files="$QDRANT_COLLECTIONS_FILE $QDRANT_SNAPSHOTS_FILE $QDRANT_ALIAS_RECOVERY_HISTORY_FILE $QDRANT_COLLECTION_ALIASES $QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE $QDRANT_FAILED_RECOVERY_FILE"
  local bk="$1"
  for file in $files; do
    if [ -f "$file" ]; then
      if [ "$bk" = "false" ]; then
        _printf "deleting %s file\n" "$file"
        rm "$file"
      else
        _printf "deleting and backing up %s file\n" "$file"
        now="$(date '+%Y-%m-%d_%H-%M-%S')"
        mv "$file" "$file-$now.bkp"
      fi
    fi
  done
}

# gets qdrant peer host url using cluster info endpoint. Sets the port to 6333 the http port.
get_peers_from_cluster_info() {
  local host="${source_hosts[0]}"
  result=$(_curl GET "$host/cluster" --header "api-key: $QDRANT_API_KEY")
  entries=$(jq -r '.result.peers' <<< "$result")
  peer_uri_entries=$(jq -r 'to_entries[] | "\(.key) \(.value.uri)"' <<< "$entries")

  while read -r id uri; do
    local _uri="${uri%?????}6333"
    peer_uri_map["$id"]="$_uri"
    _printf "registered peer %s with %s uri\n" "$id" "$_uri"
  done <<< "$peer_uri_entries"

  if [ ${#peer_uri_map[@]} -eq 0 ]; then
    _printf "no registered host %s exiting" "$host"
  fi
}

# initialize minio client
setup_s3_storage() {
  local result=""
  if result=$(mc alias --json set "$QDRANT_S3_ALIAS" "$QDRANT_S3_ENDPOINT_URL" "$QDRANT_S3_ACCESS_KEY_ID" "$QDRANT_S3_SECRET_ACCESS_KEY"); then
    _printf "s3 storage client configured successfully for %s!\n" "$QDRANT_S3_ENDPOINT_URL"
  fi

  status=$(jq -r '.status' <<< "$result")

  if [ "$status" != "success" ]; then
    _printf "failed to setup s3 client storage. Kindly check the s3 credentials and url, got this instead %s.\n" "${result//[[:space:]]/}"
    exit 1
  fi
}

# Dependency checks
check_dependencies() {
    local missing_deps=()

    for cmd in curl jq mc; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing_deps+=("${cmd}")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        _printf "Missing required dependencies: %s. Please install them and try again.\n" "${missing_deps[*]}"
        exit 1
    fi
}

usage() {
  local command="${1:-*}"
  if [ "$command" = "*" ]; then
    cat <<EOF
Usage: $0 <task> [OPTIONS]

Positional arguments:
  task                  Name of the task (required) i.e;

                        get_coll - fetch collections currently on the source server(s).
                        get_snap - fetch collection snapshots ^.
                        get_colla - fetch collection aliases ^.
                        create_snap - creates collection snapshots ^.
                        recover_colla - recover/restore collection aliases to the new server(s)
                        recover_snap - recover/restore collection snapshots ^.
                        reset - clear the temporary/state files created on this workspace

Optional arguments:
  -h, --help            Show this help message and exit

Environment variables:
  QDRANT_API_KEY                  - Qdrant API key
  QDRANT_SOURCE_HOSTS             - Comma-separated source hosts (required)
  QDRANT_RESTORE_HOSTS            - Comma-separated restore hosts (required)
  QDRANT_S3_ENDPOINT_URL          - S3 endpoint URL (for S3 operations)
  QDRANT_S3_ACCESS_KEY_ID         - S3 access key ID (for S3 operations)
  QDRANT_S3_SECRET_ACCESS_KEY     - S3 secret access key (for S3 operations)
  QDRANT_S3_BUCKET_NAME           - S3 bucket name (for S3 operations)
  GET_PEERS_FROM_CLUSTER_INFO     - Set to "true" to auto-discover peers
  CURL_TIMEOUT                    - Curl timeout in seconds (default: 300)
  QDRANT_WAIT_ON_TASK             - Waits for async tasks to finish
  QDRANT_SNAPSHOT_DATETIME_FILTER - Specify the datea and time filter for snapshots to be fetched and/or restored, format YYYY-mm-dd, e,g "2026-01-29-11-44", default value is empty so it will fetch every snapshot!!
Examples:
  $0 get_snap
  $0 recover_snap
  $0 reset --bkp true
EOF
  elif [ "$command" = "reset" ]; then

    cat <<EOF
Usage: $0 reset [OPTIONS]

Clear temporary files created during backup/recovery operations.

Optional arguments:
  --bkp BACKUP          Set to "true" to backup files before deletion (default: false)
  -h, --help            Show this help message and exit

Example:
  $0 reset --bkp true
EOF
  fi
}

run() {
  check_dependencies

  if [ "$#" -lt 1 ]; then
      usage
      exit 1
  fi

  local command="$1"
  shift

  get_hosts

  if [ "$GET_PEERS_FROM_CLUSTER_INFO" = "true" ]; then
    get_peers_from_cluster_info
  fi

  if [ "$command" = "get_coll" ] || [ "$command" = "get_collection" ]; then
    get_collections
  elif [ "$command" = "get_snap" ] || [ "$command" = "get_snapshot" ]; then
    local DATETIME="${QDRANT_SNAPSHOT_DATETIME_FILTER:-}"
    generate_snapshot_file_from_instance "$DATETIME"
  elif [ "$command" = "get_snap_s3" ] || [ "$command" = "get_snapshot_s3" ]; then
    setup_s3_storage
    local DATETIME="${QDRANT_SNAPSHOT_DATETIME_FILTER:-}"
    generate_snapshot_file_from_s3 "$DATETIME"
  elif [ "$command" = "create_snap" ] || [ "$command" = "create_snapshot" ]; then
    create_collection_snapshot
  elif [ "$command" = "recover_snap" ]; then
    setup_s3_storage
    local DATETIME="${QDRANT_SNAPSHOT_DATETIME_FILTER:-}"
    recover_collection_snapshots "$DATETIME"
  elif [ "$command" = "get_colla" ] || [ "$command" = "get_collection_alias" ]; then
    get_collection_aliases
  elif [ "$command" = "recover_colla" ] || [ "$command" = "recover_collection_alias" ]; then
    recover_collection_aliases
  elif [ "$command" = "reset" ]; then
    local BACKUP=false
    while [[ $# -gt 0 ]]; do
        case $1 in
            --bkp) BACKUP="$2"; shift 2 ;;
            -h|--help) usage "$command"; exit 0 ;;
            *) echo "unknown option: $1"; usage "$command"; exit 1 ;;
        esac
    done
    delete_files "$BACKUP"
  else
    printf "command unknown: %s" "$command"
    usage
    exit 1
  fi

  exit 0
}

run "$@"
