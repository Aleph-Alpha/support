#!/usr/bin/env bash

set -oue pipefail
QDRANT_COLLECTIONS_FILE="collections"
QDRANT_SNAPSHOTS_FILE="snapshots"
QDRANT_FAILED_RECOVERY_FILE="failed_snapshot_recovery"
QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE="snapshot_recovery_history"
QDRANT_ALIAS_RECOVERY_HISTORY_FILE="alias_recovery_history"
QDRANT_COLLECTION_ALIASES="collection_aliases"
BACKUP_COLLECTION_ALIASES_ON_S3=${BACKUP_COLLECTION_ALIASES_ON_S3:-false}
QDRANT_COLLECTION_ALIASES_BACKUP_FOLDER="collection_aliases_store"
QDRANT_WAIT_ON_TASK=${QDRANT_WAIT_ON_TASK:-true}
CURL_TIMEOUT="${CURL_TIMEOUT:-1800}"
QDRANT_S3_ALIAS="qdrant_s3_snapshot"
QDRANT_S3_LINK_EXPIRY_DURATION="${QDRANT_S3_LINK_EXPIRY_DURATION:-3600s}"
QDRANT_HTTP_PORT="${QDRANT_HTTP_PORT:-6333}"
QDRANT_COLLECTION_ALIASES_STABLE_FILE="${QDRANT_COLLECTION_ALIASES_STABLE_FILE:-collection_aliases}"

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

  local host="${source_hosts[0]:-}"
  if [[ -z "$host" ]]; then
    _printf "source host is not available for fetching collections. Please ensure QDRANT_SOURCE_HOSTS is set correctly in your environment variables.\n"
    exit 1
  fi

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

  # Guard against the bash `<<<` quirk: a here-string of an empty value still
  # produces a single newline, so the loop below would iterate once with an
  # empty item and write a bogus `host,` line to $QDRANT_COLLECTIONS_FILE.
  if [[ -z "$_result" ]]; then
    return
  fi

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
    local host="${source_hosts[0]:-}"
    if [[ -z "$host" ]]; then
      _printf "source host is not available for fetching collection snapshots. Please ensure QDRANT_SOURCE_HOSTS is set correctly in your environment variables.\n"
      exit 1
    fi
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
      declare -a peer_uri_pass;
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
          if [[ -n "${peer_uri_pass[peer_id]+x}" ]]; then # skip already visited peers
              continue
          fi
          peer_url=${peer_uri_map[$peer_id]}
          peer_uri_pass["$peer_id"]=1
          create_snapshot_from_peer "$peer_url" "$collection_name"
        done <<< "$remote_shards_result"
      else
        _printf "[%s] could not find remote shard(s) for %s collection on peer.\n" "$peer_url" "$collection_name"
      fi
      peer_uri_pass=()
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

  local v2_skipped_count=0
  _result=$(jq -c '.result // [] | .[]' <<< "$result")
  while read -r item; do
    local snapshot_name=""
    snapshot_name=$(jq -r '.name' <<< "$item")

    # Sanctioned narrow exception to §10 (legacy behavior frozen): once v2
    # shard snapshots exist, this endpoint lists them unfiltered alongside
    # genuine legacy collection-level snapshots (spike (e2), 2026-08-11
    # addendum) — mirrors the identical, already-sanctioned fix to the
    # sibling S3-listing path (filter_legacy_snapshot_keys); scoped the same
    # way: skip v2-shaped names only, nothing else about legacy behavior
    # changes.
    if ! printf '%s\n' "$snapshot_name" | filter_legacy_snapshot_names "$collection_name" | grep -q .; then
      ((v2_skipped_count=v2_skipped_count+1))
      continue
    fi

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

  if [ "$v2_skipped_count" -gt 0 ]; then
    _printf "[%s] skipped %d v2 shard-shaped name(s) for %s collection — use recover_snap_shards\n" \
      "$host" "$v2_skipped_count" "$collection_name"
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

    if ! printf '%s\n' "$snapshot_name" | filter_legacy_snapshot_keys | grep -q .; then
      continue
    fi

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

# discovers collection names from the S3 snapshots prefix and stores them in $QDRANT_COLLECTIONS_FILE
fetch_collections_from_s3() {
  local prefix="snapshots"
  local result=""

  _printf "fetching collections from s3 bucket %s under %s/\n" "$QDRANT_S3_BUCKET_NAME" "$prefix"

  result=$(mc ls --json "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$prefix/")

  if [ "$result" = "" ]; then
    _printf "no collections found in s3 path: %s/%s/ ...skipping!\n" "$QDRANT_S3_BUCKET_NAME" "$prefix"
    return
  fi

  collections_count=0
  _result=$(jq -c '.' <<< "$result")

  while read -r item; do
    local status=""
    local object_key=""
    local collection_name=""

    status=$(jq -r '.status?' <<< "$item")
    if [ "$status" != "success" ]; then
      _printf "failed to list collections from s3, got this instead %s\n" "${item//[[:space:]]/}"
      continue
    fi

    object_key=$(jq -r '.key' <<< "$item")       # e.g. "my_collection/" from mc ls on snapshots/
    object_key="${object_key%/}"                 # strip trailing slash (folder marker)
    collection_name="${object_key##*/}"          # use last path segment as collection name

    if [[ -z "$collection_name" || "$collection_name" == "$prefix" ]]; then
      continue
    fi

    ((collections_count=collections_count+1))
    printf ',%s\n' "$collection_name" >> $QDRANT_COLLECTIONS_FILE
  done <<< "$_result"

  _printf "%s file updated, found %d collection(s) from s3!\n" "$QDRANT_COLLECTIONS_FILE" "$collections_count"
  collections_count=0
}

# generates a list of collection snapshots from a s3 and appends it to $QDRANT_SNAPSHOTS_FILE
generate_snapshot_file_from_s3() {
  local datetime="${1:-}"

  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
    fetch_collections_from_s3
  fi

  if [ ! -f "$QDRANT_COLLECTIONS_FILE" ]; then
    _printf "non error exit since file %s does not exist.\n" "$QDRANT_COLLECTIONS_FILE"
    exit 0
  fi

  snapshot_count=0

  touch "$QDRANT_SNAPSHOTS_FILE"

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
      _printf "failed to fetch snapshots for collections %s, got this instead %s\n" "$collection_name" "${result//[[:space:]]/}"
      return 1
  fi

  s3_presigned_url=$(jq -r '.share' <<< "$result")
  return 0
}

# restores an collection snapshot from an s3 url updates the $QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE and $QDRANT_FAILED_RECOVERY_FILE
recover_collection_snapshot() {
    local host="$1"
    local collection_name="$2"
    local snapshot_name="$3"
    local result=""
    local status=""

    _printf "[%s] started to recover %s snapshot of %s collection...\n" "$host" "$snapshot_name" "$collection_name"

    if ! get_s3_url "$collection_name" "$snapshot_name"; then
      ((fail_recovered_count=fail_recovered_count+1))
      _printf "[%s] failed to presign S3 URL for %s snapshot of %s collection, skipping recover request\n" "$host" "$snapshot_name" "$collection_name"
      printf '%s,%s,%s\n' "$host" "$snapshot_name" "presign_failed" >> $QDRANT_FAILED_RECOVERY_FILE
      return
    fi

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
  local host="${source_hosts[0]:-}"
  if [[ -z "$host" ]]; then
    _printf "source host is not available for fetching collection aliases. Please ensure QDRANT_SOURCE_HOSTS is set correctly in your environment variables.\n"
    exit 1
  fi
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

  : > "$QDRANT_COLLECTION_ALIASES"

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

if [ "$BACKUP_COLLECTION_ALIASES_ON_S3" = "true" ]; then

    setup_s3_storage

    local ts
    ts=$(date '+%Y-%m-%d_%H-%M-%S')

    local base_path="$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$QDRANT_COLLECTION_ALIASES_BACKUP_FOLDER"

    local versioned_dest="$base_path/${QDRANT_COLLECTION_ALIASES}-$ts"
    local stable_dest="$base_path/${QDRANT_COLLECTION_ALIASES}"

    _printf "backing up collection aliases to s3 bucket %s\n" "$QDRANT_S3_BUCKET_NAME"

    if ! mc cp "$QDRANT_COLLECTION_ALIASES" "$versioned_dest"; then
      _printf "failed to upload versioned collection aliases backup to %s\n" "$QDRANT_S3_BUCKET_NAME"
      exit 1
    fi

    if ! mc cp "$versioned_dest" "$stable_dest"; then
      _printf "failed to update collection aliases stable backup pointer in %s\n" "$QDRANT_S3_BUCKET_NAME"
      exit 1
    fi

    _printf "successfully backed up collection aliases to s3 bucket %s\n" "$QDRANT_S3_BUCKET_NAME"
  fi

  _printf "%s file updated,found %d collection alias(es)!\n" "$QDRANT_COLLECTION_ALIASES" "$colla_length"
}

# restores collection alias to a qdrant node and appends progress to $QDRANT_ALIAS_RECOVERY_HISTORY_FILE
recover_collection_alias() {
  local collection_name="$1"
  local alias_name="$2"
  local host="$3"
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
    _printf "[%s] failed to restore collection alias %s:%s, got this instead %s\n" "$host" "$collection_name" "$alias_name" "${result//[[:space:]]/}"
    return
  fi

  ((recovered_colla_count=recovered_colla_count+1))
  printf '%s,%s,%s\n' "$collection_name" "$alias_name" "$status" >> $QDRANT_ALIAS_RECOVERY_HISTORY_FILE
}

# restores collection aliases to a qdrant node and appends progress to $QDRANT_ALIAS_RECOVERY_HISTORY_FILE
recover_collection_aliases() {

  local host="${restore_hosts[0]:-}"
  if [[ -z "$host" ]]; then
    _printf "restore host is not available for recovering collection aliases. Please ensure QDRANT_RESTORE_HOSTS is set correctly in your environment variables.\n"
    exit 1
  fi


  if [ "$BACKUP_COLLECTION_ALIASES_ON_S3" = "true" ]; then

    setup_s3_storage

    if mc cp "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$QDRANT_COLLECTION_ALIASES_BACKUP_FOLDER/$QDRANT_COLLECTION_ALIASES_STABLE_FILE" "$QDRANT_COLLECTION_ALIASES"; then
      _printf "collection aliases restored from s3 bucket %s\n" "$QDRANT_S3_BUCKET_NAME"
    else
      _printf "failed to restore collection aliases file (%s) from s3 bucket %s\n" "$QDRANT_COLLECTION_ALIASES_STABLE_FILE" "$QDRANT_S3_BUCKET_NAME"
      exit 1
    fi
  fi

  if [ ! -f "$QDRANT_COLLECTION_ALIASES" ]; then
      _printf "collection aliases file does not exist, run 'get_colla' task to fetch collection aliases from source hosts or enable BACKUP_COLLECTION_ALIASES_ON_S3 to fetch collection aliases from S3 bucket\n"
      return
  fi

  colla_count=$(wc -l < $QDRANT_COLLECTION_ALIASES)
  recovered_colla_count=0
  failed_recovered_colla_count=0
  colla_skipped_count=0

  touch $QDRANT_ALIAS_RECOVERY_HISTORY_FILE


  while IFS= read -r line; do
    IFS=',' read -ra cols <<< "$line"
    local collection_name="${cols[0]}"
    local alias_name="${cols[1]}"

    history_count=$(grep -cw "$collection_name,$alias_name,ok" "$QDRANT_ALIAS_RECOVERY_HISTORY_FILE" || true)

    if [ "$history_count" -gt 0 ]; then
      _printf "[%s] collection alias %s:%s already recovered, skipping!\n" "$host" "$collection_name" "$alias_name"
      ((colla_skipped_count=colla_skipped_count+1))
      continue
    fi
    recover_collection_alias "$collection_name" "$alias_name" "$host"
  done < $QDRANT_COLLECTION_ALIASES

  _printf "recovery summary: %d/%d collection aliases recovered, %d failed, %d skipped.\n" "$recovered_colla_count" "$colla_count" "$failed_recovered_colla_count" "$colla_skipped_count"

  colla_count=0
  recovered_colla_count=0
  failed_recovered_colla_count=0
}

# removes state files with(out) backup
delete_files() {
  local files="$QDRANT_COLLECTIONS_FILE $QDRANT_SNAPSHOTS_FILE $QDRANT_ALIAS_RECOVERY_HISTORY_FILE $QDRANT_COLLECTION_ALIASES $QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE $QDRANT_FAILED_RECOVERY_FILE $QDRANT_SHARD_RECOVERY_HISTORY_FILE"
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

# gets qdrant peer host url using cluster info endpoint. Sets the port to $QDRANT_HTTP_PORT the http port.
get_peers_from_cluster_info() {
  local host="${source_hosts[0]:-}"
  if [[ -z "$host" ]]; then
    _printf "source host is not available. Please ensure QDRANT_SOURCE_HOSTS is set correctly in your environment variables. If restoring snapshots set QDRANT_SOURCE_HOSTS and GET_PEERS_FROM_CLUSTER_INFO to empty string.\n"
    exit 1
  fi

  result=$(_curl GET "$host/cluster" --header "api-key: $QDRANT_API_KEY")
  entries=$(jq -r '.result.peers // {}' <<< "$result")
  peer_uri_entries=$(jq -r 'to_entries[] | "\(.key) \(.value.uri)"' <<< "$entries")

  while read -r id uri; do
    local _uri="${uri%:*}:$QDRANT_HTTP_PORT"
    peer_uri_map["$id"]="$_uri"
    _printf "registered peer %s with %s uri\n" "$id" "$_uri"
  done <<< "$peer_uri_entries"

  if [ ${#peer_uri_map[@]} -eq 0 ]; then
    _printf "no registered host peers in %s... exiting\n" "$host"
    exit 1
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
                        create_snap_shards - per-shard backup + manifest + retention (per-shard)
                        prune_snap - retention; --legacy prunes old per-node snapshots (per-shard)
                        recover_snap_shards - manifest-driven per-shard restore + verify (per-shard)

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
  CURL_TIMEOUT                    - Curl timeout in seconds (default: 1800)
  QDRANT_WAIT_ON_TASK             - Waits for async tasks to finish
  QDRANT_SNAPSHOT_DATETIME_FILTER - Specify the date and time filter for snapshots to be fetched and/or restored, format YYYY-mm-dd, e,g "2026-01-29-11-44", default value is empty so it will fetch every snapshot!!
  QDRANT_BACKUP_RETENTION_SETS    - Number of per-shard backup sets to retain per collection (per-shard, default: 2; 0 makes create_snap_shards SKIP its automatic retention pass entirely, but a manual prune_snap still clamps to 1 and DELETES every other set)
  QDRANT_LEGACY_KEEP_RUNS         - Legacy per-node snapshots to keep per (collection,peer) with prune_snap --legacy (per-shard, default: 2, must be >= 1)
  QDRANT_RESTORE_FORCE            - Set to "true" to delete+recreate a non-empty/incompatible target collection on restore (per-shard, default: false)
  QDRANT_SKIP_VERSION_CHECK       - Set to "true" to bypass the restore version gate (per-shard, default: false)
  QDRANT_VERIFY_TOLERANCE_PCT     - Restored point-count tolerance percentage for restore verification (per-shard, integer 0-100, default: 1)
  QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS - Max seconds to wait for green status and for the replica-set check to pass during restore verification (per-shard, default: 1800)
  QDRANT_VERIFY_POLL_INTERVAL_SECONDS - Seconds between polls while waiting on the above (per-shard, default: 5, must be >= 1)
  QDRANT_VERIFY_SAMPLE_POINTS     - Random points whose payloads restore verification probe-reads in batches of <= 100 (per-shard, default: 300; 0 disables the probes, loudly)
  QDRANT_SWEEP_DELETE_CAP_PCT     - Max percent of objects prune_snap may delete as orphans in one pass (per-shard, default: 50)
  QDRANT_SWEEP_GRACE_SECONDS      - Minimum object age (seconds) before prune_snap's orphan sweep may delete it (per-shard, default: 172800 = 48h)
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

  case "$command" in
    create_snap_shards|prune_snap|recover_snap_shards) : ;;
    *) if [ "$GET_PEERS_FROM_CLUSTER_INFO" = "true" ]; then get_peers_from_cluster_info; fi ;;
  esac

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
    # create collection snapshots
    create_collection_snapshot

    # backup collection aliases to s3 bucket
    get_collection_aliases

  elif [ "$command" = "recover_snap" ]; then
    setup_s3_storage
    local DATETIME="${QDRANT_SNAPSHOT_DATETIME_FILTER:-}"
    recover_collection_snapshots "$DATETIME"

    # restore collection aliases from s3 bucket
    recover_collection_aliases

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
  elif [ "$command" = "create_snap_shards" ]; then
    create_snap_shards_task "$@"
  elif [ "$command" = "prune_snap" ]; then
    prune_snap_task "$@"
  elif [ "$command" = "recover_snap_shards" ]; then
    recover_snap_shards_task "$@"
  else
    printf "command unknown: %s" "$command"
    usage
    exit 1
  fi

  exit 0
}

# ============================================================================
# Per-shard backup/restore
# (§ shorthand in comments refers to the "Qdrant per-shard backup design"
# document, 2026-08-10 — maintained outside this repo.)
# New code only below this line — legacy functions above are frozen: the ConfigMap injector ships every
# merge straight to the production CronJob, so legacy behavior must never change.
# ============================================================================

# The shipped Job/CronJob manifests run readOnlyRootFilesystem with only the
# workdir writable — default TMPDIR to CWD so mktemp works in the container.
: "${TMPDIR:=$PWD}"
export TMPDIR

QDRANT_BACKUP_RETENTION_SETS="${QDRANT_BACKUP_RETENTION_SETS:-2}"
QDRANT_LEGACY_KEEP_RUNS="${QDRANT_LEGACY_KEEP_RUNS:-2}"
QDRANT_RESTORE_FORCE="${QDRANT_RESTORE_FORCE:-false}"
QDRANT_SKIP_VERSION_CHECK="${QDRANT_SKIP_VERSION_CHECK:-false}"
QDRANT_VERIFY_TOLERANCE_PCT="${QDRANT_VERIFY_TOLERANCE_PCT:-1}"
QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS="${QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS:-1800}"
QDRANT_VERIFY_POLL_INTERVAL_SECONDS="${QDRANT_VERIFY_POLL_INTERVAL_SECONDS:-5}"
QDRANT_VERIFY_SAMPLE_POINTS="${QDRANT_VERIFY_SAMPLE_POINTS:-300}"
QDRANT_SWEEP_DELETE_CAP_PCT="${QDRANT_SWEEP_DELETE_CAP_PCT:-50}"
QDRANT_SWEEP_GRACE_SECONDS="${QDRANT_SWEEP_GRACE_SECONDS:-172800}"
QDRANT_SHARD_RECOVERY_HISTORY_FILE="shard_recovery_history"

# Shared jq: normalize a GET /collections/{c}/cluster response into a flat
# replica array [{shard_id, peer_id, state}]. Used by select_shard_peers,
# check_replica_sets, and later per-shard peer lookups.
readonly JQ_NORMALIZE_REPLICAS='
  .result as $r |
  ([ $r.local_shards[]? | {shard_id, peer_id: $r.peer_id, state} ] +
   [ $r.remote_shards[]? | {shard_id, peer_id, state} ])'

# stdin: Qdrant response JSON → stdout observed status. rc 0 only when "ok".
# "accepted", unknown, unparseable and empty bodies are NEVER success.
qdrant_status_ok() {
  local s
  if ! s=$(jq -r '.status // "unknown"' 2>/dev/null); then s="unparseable"; fi
  if [ -z "$s" ]; then s="empty-body"; fi
  printf '%s' "$s"
  if [ "$s" = "ok" ]; then return 0; fi
  return 1
}

# Legacy discovery must never see per-shard keys. Keys from `mc ls -r` on
# snapshots/{c} are collection-relative, so per-shard segments can be LEADING.
# Patterns are path-segment-anchored: a collection named e.g. restore_state_v1
# keeps its legacy snapshots.
filter_legacy_snapshot_keys() {
  grep -v -e '^shards/' -e '/shards/' \
          -e '^backup_manifests/' -e '/backup_manifests/' \
          -e '^restore_state/' -e '/restore_state/' || true
}

# Sibling guard for the legacy API-listing path (`GET /collections/{c}/
# snapshots`, used by fetch_collection_snapshot): unlike `mc ls -r` keys,
# these are bare snapshot NAMES with no path separators, so
# filter_legacy_snapshot_keys' path-segment patterns don't apply — verified
# empirically against a live cluster (spike (e2), 2026-08-11 addendum):
# legacy collection-level names are "{collection}-{peer_id}-{timestamp}.snapshot";
# per-shard (shard-level) names are "{collection}-shard-{shard_id}-{timestamp}.snapshot".
# stdin: snapshot names (one per line). $1: collection name (used LITERALLY).
# Emits names that are NOT per-shard snapshots ({c}-shard-{N}-...). Metachar-proof:
# the collection prefix is stripped by parameter expansion, never used as a regex.
filter_legacy_snapshot_names() {
  local collection="$1" name rest
  while IFS= read -r name; do
    rest="${name#"$collection"-shard-}"
    if [ "$rest" = "$name" ] || [[ ! "$rest" =~ ^[0-9]+- ]]; then
      printf '%s\n' "$name"
    fi
  done
}

# Peer discovery: associative array mapping peer_id -> peer_url.
declare -A peer_url_by_id

# stdin: GET /collections/{c}/cluster JSON
# stdout: "shard_id,peer_id" lines — one Active replica per shard, round-robin.
# rc 3 when a shard has no Active replica or cluster has no shards.
select_shard_peers() {
  local out
  if out=$(jq -r "$JQ_NORMALIZE_REPLICAS"' as $reps |
    ($reps | map(.shard_id) | unique | sort) as $shards |
    if ($shards | length) == 0 then error("no shards found in cluster input") else
    $shards | to_entries | map(
      .key as $idx | .value as $sid |
      ([ $reps[] | select(.shard_id == $sid and .state == "Active") | .peer_id ]
        | sort) as $peers |
      if ($peers | length) == 0
      then error("shard \($sid) has no Active replica")
      else "\($sid),\($peers[$idx % ($peers | length)])"
      end) | .[]
    end'); then
    printf '%s\n' "$out"
    return 0
  fi
  _printf "shard peer selection failed for cluster input\n" >&2
  return 3
}

# $1: collection-info JSON file   $2: cluster JSON file
# rc 0 ok | 3 custom sharding OR unreadable collection info | 4 transfers/resharding in flight OR unreadable cluster info | 5 no Active replica
check_preconditions() {
  local sharding transfers resharding probe_err
  if ! sharding=$(jq -r '.result.config.params.sharding_method // "auto"' "$1"); then
    _printf "precondition failed: cannot read/parse collection info %s\n" "$1"
    return 3
  fi
  if [ "$sharding" = "custom" ]; then
    _printf "precondition failed: custom sharding is not supported by per-shard backup\n"
    return 3
  fi
  if ! transfers=$(jq -r '(.result.shard_transfers // []) | length' "$2"); then
    _printf "precondition failed: cannot read/parse cluster info %s\n" "$2"
    return 4
  fi
  if ! resharding=$(jq -r '(.result.resharding_operations // []) | length' "$2"); then
    _printf "precondition failed: cannot read/parse cluster info %s\n" "$2"
    return 4
  fi
  if [ "$transfers" -gt 0 ] || [ "$resharding" -gt 0 ]; then
    _printf "precondition failed: %s transfer(s), %s resharding op(s) in flight\n" \
      "$transfers" "$resharding"
    return 4
  fi
  local want got
  want=$(jq -r '.result.config.params.shard_number // 0' "$1")
  got=$(jq -r "$JQ_NORMALIZE_REPLICAS"' | map(.shard_id) | unique | length' "$2")
  if [ "$want" -gt 0 ] && [ "$got" -ne "$want" ]; then
    _printf "precondition failed: cluster reports %s shard(s), config says %s\n" "$got" "$want"
    return 5
  fi
  if ! probe_err=$(select_shard_peers < "$2" 2>&1 > /dev/null); then
    _printf "precondition failed: %s\n" "${probe_err:-at least one shard has no Active replica}"
    return 5
  fi
  return 0
}

# stdin: GET /collections/{c} JSON  → stdout: PUT /collections/{c} body.
map_config_get_to_put() {
  jq '{
    vectors: .result.config.params.vectors,
    shard_number: .result.config.params.shard_number,
    replication_factor: .result.config.params.replication_factor,
    write_consistency_factor: .result.config.params.write_consistency_factor,
    on_disk_payload: .result.config.params.on_disk_payload,
    sparse_vectors: .result.config.params.sparse_vectors,
    payload: .result.config.params.payload,
    hnsw_config: .result.config.hnsw_config,
    optimizers_config: .result.config.optimizer_config,
    wal_config: .result.config.wal_config,
    strict_mode_config: .result.config.strict_mode_config,
    metadata: .result.config.metadata,
    quantization_config: .result.config.quantization_config
  } | walk(if type == "object" then with_entries(select(.value != null)) else . end)'
}

# stdin: one `mc stat --json` response. stdout: "<etag>\t<size>" on rc 0.
# rc 1 (reason on stderr) when the etag is missing/empty or the size is not a
# positive number — a shard object whose at-rest identity cannot be read must
# fail that collection's backup (fail-closed), never yield a schema-2 manifest
# with hollow integrity fields. The etag is recorded and later compared as an
# OPAQUE string only (multipart ETags are not MD5 — never treat it as one).
parse_stat_etag_size() {
  local input etag size
  input=$(cat)
  etag=$(jq -r '.etag // ""' <<<"$input" 2>/dev/null) || etag=""
  size=$(jq -r 'if (.size | type) == "number" then .size else "" end' <<<"$input" 2>/dev/null) || size=""
  if [ -z "$etag" ]; then
    _printf "parse_stat_etag_size: stat carries no etag\n" >&2
    return 1
  fi
  if ! [[ "$size" =~ ^[0-9]+$ ]] || [ "$size" -eq 0 ]; then
    _printf "parse_stat_etag_size: stat size '%s' is not a positive integer\n" "$size" >&2
    return 1
  fi
  printf '%s\t%s' "$etag" "$size"
}

# stdin: {set_id, collection, qdrant_version, git_ref, collection_info, aliases, shards, pc?}
# `pc` (optional) is a fresher points_count read after the shard loop; falls back
# to the collection_info snapshot taken before it when absent.
# schema 2 (integrity wave): each shard entry carries the S3 object's `etag`
# and `size` as observed by the backup-side `mc stat` — this lets the restore
# pre-flight prove the object is UNCHANGED SINCE BACKUP (at-rest tamper/rot/
# truncation detection). It does NOT prove validity: if Qdrant wrote a corrupt
# object at backup time, its recorded ETag is the corrupt object's. The deep
# payload smoke scroll at restore verification is the end-to-end served-data
# counterpart — the two are a pair, not alternatives.
build_manifest() {
  jq '{
    schema_version: 2,
    backup_set_id: .set_id,
    collection: .collection,
    qdrant_version: .qdrant_version,
    sharding_method: (.collection_info.result.config.params.sharding_method // "auto"),
    shard_count: .collection_info.result.config.params.shard_number,
    points_count: (.pc // .collection_info.result.points_count // 0),
    collection_config: .collection_info.result,
    aliases: (.aliases // []),
    shards: .shards,
    created_by: ("qdrant_backup_recovery.sh@" + (.git_ref // "unknown"))
  }'
}

# stdin: manifest JSON. rc 0 valid / 1 invalid (failed checks named on stderr).
# Schema acceptance: 1 ACCEPTED (pre-integrity-fields manifests exist only in
# lab buckets; the restore pre-flight flags them loudly), 2 ENFORCED (every
# shard entry must carry a non-empty etag and a numeric size), anything else
# REJECTED.
validate_manifest() {
  local input failures
  input=$(cat)
  if [ -z "${input//[[:space:]]/}" ]; then
    _printf "manifest validation failed: empty input\n" >&2
    return 1
  fi
  if ! failures=$(jq -r '
      [
        (if (.schema_version == 1 or .schema_version == 2) then empty else "schema_version not 1 or 2" end),
        (if .schema_version == 2 then
           (if all((.shards // [])[]; (.etag | type == "string" and length > 0)) then empty
            else "schema 2 shard missing/empty etag" end)
         else empty end),
        (if .schema_version == 2 then
           (if all((.shards // [])[]; (.size | type == "number")) then empty
            else "schema 2 shard size not numeric" end)
         else empty end),
        (if (.backup_set_id | type == "string" and length > 0) then empty else "backup_set_id missing/empty" end),
        (if (.collection | type == "string" and length > 0) then empty else "collection missing/empty" end),
        (if (.shard_count | type == "number") then empty else "shard_count not numeric" end),
        (if ((.shards // []) | length) == .shard_count then empty else "shards length != shard_count" end),
        (if ((.shards // []) | map(.id) | unique | length) == ((.shards // []) | length) then empty else "duplicate shard ids" end),
        (if all((.shards // [])[]; (.s3_key | type == "string" and length > 0) and (.snapshot_name | type == "string" and length > 0)) then empty else "shard missing s3_key/snapshot_name" end),
        (if (.collection_config | type == "object") then empty else "collection_config missing/invalid" end)
      ] | join("; ")' <<<"$input" 2>&1); then
    _printf "manifest validation failed: unparseable manifest JSON: %s\n" "${failures:-no detail}" >&2
    return 1
  fi
  if [ -z "$failures" ]; then
    return 0
  fi
  _printf "manifest validation failed: %s\n" "$failures" >&2
  return 1
}

# $1 manifest version  $2 target version  $3 skip ("true"/"false")
# rc 0 pass (stdout WARNING on n+1) | rc 5 blocked. Qdrant supports restoring onto the same or next minor only.
check_version_gate() {
  if [ "$3" = "true" ]; then
    _printf "WARNING: version gate skipped by QDRANT_SKIP_VERSION_CHECK\n"
    return 0
  fi
  local mmaj mmin tmaj tmin
  mmaj=$(cut -d. -f1 <<<"$1"); mmin=$(cut -d. -f2 <<<"$1")
  tmaj=$(cut -d. -f1 <<<"$2"); tmin=$(cut -d. -f2 <<<"$2")
  if ! [[ "$mmaj" =~ ^[0-9]+$ && "$mmin" =~ ^[0-9]+$ && "$tmaj" =~ ^[0-9]+$ && "$tmin" =~ ^[0-9]+$ ]]; then
    _printf "version gate: cannot parse versions '%s' vs '%s'\n" "$1" "$2"
    return 5
  fi
  if [ "$mmaj" != "$tmaj" ]; then
    _printf "version gate: major version differs (%s vs %s)\n" "$1" "$2"
    return 5
  fi
  if [ "$tmin" = "$mmin" ]; then return 0; fi
  if [ "$tmin" = "$((mmin + 1))" ]; then
    _printf "WARNING: restoring %s snapshot onto next minor %s (docs allow n+1)\n" "$1" "$2"
    return 0
  fi
  _printf "version gate: %s is not within one minor of %s\n" "$2" "$1"
  return 5
}

# $1 filter (may be empty). stdin: JSON array of {set_id}. stdout: chosen set_id.
# rc 4 when a non-empty filter matches nothing (available ids on stderr).
select_backup_set() {
  local filter="${1:-}" ids id chosen=""
  if ! ids=$(jq -r 'map(.set_id) | sort | .[]'); then
    _printf "select_backup_set: unparseable set list\n" >&2
    return 4
  fi
  if [ -z "$ids" ]; then
    _printf "no backup sets found\n" >&2
    return 4
  fi
  while IFS= read -r id; do
    if [ -z "$id" ]; then continue; fi
    if [ -z "$filter" ] || [[ "$id" == "$filter"* ]]; then
      chosen="$id"
    fi
  done <<<"$ids"
  if [ -z "$chosen" ]; then
    _printf "no backup set matches filter '%s'; available:\n%s\n" "$filter" "$ids" >&2
    return 4
  fi
  printf '%s\n' "$chosen"
}

# stdin: {live: <GET collection JSON>, manifest: <manifest JSON>}
# rc 0 compatible | rc 6 shard_number or vectors mismatch (details on stderr).
compare_collection_config() {
  local input ok
  input=$(cat)
  if ! ok=$(jq '
    (.live.result.config.params.shard_number != null) and
    (.manifest.collection_config.config.params.shard_number != null) and
    (.live.result.config.params.shard_number == .manifest.collection_config.config.params.shard_number)
    and (.live.result.config.params.vectors == .manifest.collection_config.config.params.vectors)
  ' <<<"$input" 2>&1); then
    _printf "compare_collection_config: unparseable input JSON: %s\n" "$ok" >&2
    return 6
  fi
  if [ "$ok" = "true" ]; then return 0; fi
  jq -r '
    [(if .live.result.config.params.shard_number != .manifest.collection_config.config.params.shard_number or .live.result.config.params.shard_number == null
      then "shard_number: live=\(.live.result.config.params.shard_number) manifest=\(.manifest.collection_config.config.params.shard_number)" else empty end),
     (if .live.result.config.params.vectors != .manifest.collection_config.config.params.vectors
      then "vectors differ" else empty end)] | join("; ") | "config mismatch: " + .
  ' <<<"$input" >&2
  return 6
}

# $1 write_consistency_factor  $2 replication_factor  $3 target peer count
# rc 0 (warn when peers < RF) | rc 8 when wcf > peers (collection create would
# yield unwritable collection).
check_capacity_gate() {
  local wcf="$1" rf="$2" peers="$3"
  if ! [[ "$wcf" =~ ^[0-9]+$ && "$rf" =~ ^[0-9]+$ && "$peers" =~ ^[0-9]+$ ]]; then
    _printf "capacity gate failed: non-numeric input wcf=%s rf=%s peers=%s\n" "$wcf" "$rf" "$peers"
    return 8
  fi
  if [ "$wcf" -gt "$peers" ]; then
    _printf "capacity gate failed: write_consistency_factor=%s > target peers=%s\n" "$wcf" "$peers"
    return 8
  fi
  if [ "$peers" -lt "$rf" ]; then
    _printf "WARNING: target has %s peers < replication_factor %s — Qdrant places min(RF, peers) replicas\n" \
      "$peers" "$rf"
  fi
  return 0
}

# $1 manifest_points  $2 restored_points  $3 tolerance_pct (integer)
# rc 0 within tolerance | rc 7 outside (hard verification failure — the restore's exit code reflects it).
check_count_tolerance() {
  local manifest="$1" restored="$2" tol="$3" delta
  if ! [[ "$manifest" =~ ^[0-9]+$ && "$restored" =~ ^[0-9]+$ && "$tol" =~ ^[0-9]+$ ]]; then
    _printf "count check failed: non-numeric input manifest=%s restored=%s tolerance=%s\n" \
      "$manifest" "$restored" "$tol"
    return 7
  fi
  if [ "$tol" -gt 100 ]; then
    _printf "count check failed: tolerance %s%% exceeds 100\n" "$tol"
    return 7
  fi
  if [ "$manifest" -eq 0 ]; then
    if [ "$restored" -eq 0 ]; then return 0; fi
    _printf "count check failed: manifest=0 restored=%s\n" "$restored"; return 7
  fi
  if [ "$restored" -ge "$manifest" ]; then delta=$((restored - manifest)); else delta=$((manifest - restored)); fi
  if [ $((delta * 100)) -le $((manifest * tol)) ]; then return 0; fi
  _printf "count check failed: manifest=%s restored=%s delta=%s tolerance=%s%%\n" \
    "$manifest" "$restored" "$delta" "$tol"
  return 7
}

# $1 keep_n. stdin: legacy basenames ({collection}-{peer_id}-{Y-m-d-H-M-S}.snapshot).
# stdout: names to DELETE (newest keep_n per (collection,peer) retained).
# Unparseable names (incl. those containing `/`) are NEVER deleted; logged to stderr.
# rc 0 | 1 non-numeric keep_n.
group_legacy_snapshots() {
  local keep="$1" line all=""
  if ! [[ "$keep" =~ ^[0-9]+$ ]]; then
    _printf "group_legacy_snapshots: keep_n must be numeric, got %s\n" "$keep" >&2
    return 1
  fi
  while IFS= read -r line; do
    if [ -z "$line" ]; then continue; fi
    if printf '%s' "$line" | grep -Eq '^.+-[0-9]+-[0-9]{4}(-[0-9]{2}){5}\.snapshot$' && [[ "$line" != */* ]]; then
      all+="$line"$'\n'
    else
      _printf "SKIP unparseable: %s\n" "$line" >&2
    fi
  done
  printf '%s' "$all" | jq -Rr --argjson keep "$keep" -s '
    split("\n") | map(select(length > 0)) |
    map(select(capture("^(?<coll>.+)-(?<peer>[0-9]+)-(?<ts>[0-9]{4}(-[0-9]{2}){5})\\.snapshot$") != null) |
        capture("^(?<coll>.+)-(?<peer>[0-9]+)-(?<ts>[0-9]{4}(-[0-9]{2}){5})\\.snapshot$") + {name: .}) |
    group_by(.coll + "/" + .peer) |
    map(sort_by(.ts) | reverse | .[$keep:] | .[].name) | .[]'
}

# $1 manifests_found  $2 objects_total  $3 delete_count
# rc 0 | 8 zero manifests or non-numeric input | 9 cap exceeded (>cap%).
check_sweep_safety() {
  if ! [[ "$1" =~ ^[0-9]+$ && "$2" =~ ^[0-9]+$ && "$3" =~ ^[0-9]+$ ]]; then
    _printf "sweep aborted: non-numeric input manifests=%s objects=%s delete=%s\n" "$1" "$2" "$3" >&2
    return 8
  fi
  if [ "$1" -eq 0 ]; then
    _printf "sweep aborted: zero manifests parsed — refusing to treat everything as orphaned\n" >&2
    return 8
  fi
  if ! [[ "$QDRANT_SWEEP_DELETE_CAP_PCT" =~ ^[0-9]+$ ]]; then
    _printf "sweep aborted: QDRANT_SWEEP_DELETE_CAP_PCT must be a non-negative integer, got '%s'\n" \
      "$QDRANT_SWEEP_DELETE_CAP_PCT" >&2
    return 9
  fi
  if [ $(( $3 * 100 )) -gt $(( $2 * QDRANT_SWEEP_DELETE_CAP_PCT )) ]; then
    _printf "sweep aborted: would delete %s of %s objects (>%s%% cap) — manual review required\n" "$3" "$2" "$QDRANT_SWEEP_DELETE_CAP_PCT" >&2
    return 9
  fi
  return 0
}

# stdin: JSON array of {set_id}. $1 keep_n. stdout: doomed set ids (oldest first),
# one per line. Empty output when count <= keep_n. rc 1 on unparseable input or a
# non-numeric/zero keep_n — the caller (prune_one_collection) clamps a valid-but-low
# keep_n to the never-delete-the-last-set floor BEFORE calling; this function never guesses on the
# caller's behalf.
select_doomed_sets() {
  local keep="$1" input out
  if ! [[ "$keep" =~ ^[0-9]+$ ]]; then
    _printf "select_doomed_sets: keep_n must be numeric, got '%s'\n" "$keep" >&2
    return 1
  fi
  if [ "$keep" -lt 1 ]; then
    _printf "select_doomed_sets: keep_n must be >= 1, got '%s'\n" "$keep" >&2
    return 1
  fi
  if ! input=$(cat); then
    _printf "select_doomed_sets: cannot read stdin\n" >&2
    return 1
  fi
  if ! jq -e 'type == "array"' <<<"$input" >/dev/null 2>&1; then
    _printf "select_doomed_sets: input is not a JSON array\n" >&2
    return 1
  fi
  if ! out=$(jq -r --argjson keep "$keep" 'map(.set_id) | sort | .[0:(length - $keep)] | .[]' <<<"$input" 2>&1); then
    _printf "select_doomed_sets: unparseable set list: %s\n" "$out" >&2
    return 1
  fi
  printf '%s\n' "$out"
}

# $1 now_epoch  $2 mtime_epoch  $3 grace_seconds. rc 0 when the object is OLD ENOUGH
# to sweep (age strictly > grace); rc 1 otherwise, INCLUDING any non-numeric input —
# fail-safe: an object whose age cannot be computed is never eligible for deletion.
sweep_age_ok() {
  local now="$1" mtime="$2" grace="$3"
  if ! [[ "$now" =~ ^[0-9]+$ && "$mtime" =~ ^[0-9]+$ && "$grace" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if [ $((now - mtime)) -gt "$grace" ]; then
    return 0
  fi
  return 1
}

# $1 candidate keep_n. rc 0 iff numeric AND >= 1. Gates BOTH QDRANT_LEGACY_KEEP_RUNS
# checks (prune_snap_task's --legacy pre-flight and prune_legacy_one's own defense-
# in-depth check) — 0 is never a legacy-prune default; escalating to exactly 1 is
# an explicit, deliberate operator act, never silently coerced from a
# garbage or zero config value (0 would delete every legacy snapshot in one pass).
legacy_keep_runs_ok() {
  local v="$1"
  if ! [[ "$v" =~ ^[0-9]+$ ]]; then return 1; fi
  if [ "$v" -lt 1 ]; then return 1; fi
  return 0
}

# $1 expected replica count. stdin: target GET /collections/{c}/cluster JSON.
# rc 0 | rc 7 with per-shard reasons (missing/non-Active/surplus incl. Partial/Dead).
check_replica_sets() {
  local expected="$1" problems input
  if ! [[ "$expected" =~ ^[0-9]+$ ]]; then
    _printf "replica set verification failed: non-numeric expected count %s\n" "$expected" >&2
    return 7
  fi
  if ! input=$(cat 2>&1); then
    _printf "replica set verification failed: cannot read cluster input\n" >&2
    return 7
  fi
  if [ -z "$input" ]; then
    _printf "replica set verification failed: unparseable cluster info\n" >&2
    return 7
  fi
  if ! problems=$(jq -r --argjson exp "$expected" "$JQ_NORMALIZE_REPLICAS"' as $reps |
    if ($reps | length) == 0 then error("no shards found in cluster input") else $reps |
    group_by(.shard_id) | map(
      {sid: .[0].shard_id,
       total: length,
       active: ([.[] | select(.state == "Active")] | length),
       partial: ([.[] | select(.state == "Partial")] | length)} |
      {sid: .sid, total: .total, active: .active, partial: .partial, other: (.total - .active - .partial)} |
      select(.total != $exp or .active != $exp or .partial > 0) |
      "shard \(.sid): \(.total) replicas (\(.active) Active, \(.partial) Partial, \(.other) other), expected \($exp) Active"
    ) | .[] end' <<<"$input" 2>&1); then
    _printf "replica set verification failed: unparseable cluster info\n" >&2
    return 7
  fi
  if [ -z "$problems" ]; then return 0; fi
  _printf "replica set verification failed:\n%s\n" "$problems"
  return 7
}

# Like legacy _curl but: no -f (error bodies captured), transport errors are
# rc 2 instead of killing the run, callers ALWAYS use `out=$(_curl_rc …) || rc=$?`.
# New code paths only — legacy _curl stays untouched (frozen legacy behavior).
# rc 2 covers both never-reached and timed-out; a timed-out request may still have
# completed server-side — idempotency-sensitive callers must not blindly retry.
_curl_rc() {
  local method="$1"; shift
  local url="$1"; shift
  local response http_code rc=0 errfile
  errfile=$(mktemp -p "${TMPDIR:-.}")
  response=$(curl -sS -w "\n%{http_code}" \
    --max-time "${CURL_TIMEOUT}" --connect-timeout 30 \
    -X "${method}" "$@" "${url}" 2>"$errfile") || rc=$?
  if [ "$rc" -ne 0 ]; then
    _printf "curl transport error (rc=%s) for %s %s: %s\n" \
      "$rc" "$method" "$url" "$(tr -d '\n' < "$errfile" | head -c 300)" >&2
    rm -f "$errfile"
    return 2
  fi
  rm -f "$errfile"
  http_code=$(tail -n1 <<<"${response}")
  sed '$d' <<<"${response}"
  if [[ "${http_code}" =~ ^2[0-9]{2}$ ]]; then return 0; fi
  return 1
}

# Check if jq output (stdin) contains an mc error payload (status == "error").
# rc 0 if error present, 1 if not. Used as a pure testable predicate.
mc_output_has_error() {
  if jq -e 'select(.status? == "error")' >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# mc with --json that distinguishes ERROR (rc 1, message on stderr) from
# legitimately EMPTY output (rc 0). Never reuse the legacy "empty means
# nothing found, continue" pattern for delete decisions.
mc_json_safe() {
  local out rc=0 errfile
  errfile=$(mktemp -p "${TMPDIR:-.}")
  out=$(mc --json "$@" 2>"$errfile") || rc=$?
  if [ "$rc" -ne 0 ]; then
    _printf "mc error (mc %s): %s\n" "$*" "$(tr -d '\n' < "$errfile" | head -c 300)" >&2
    rm -f "$errfile"
    return 1
  fi
  rm -f "$errfile"
  # Also treat mc-level error JSON (status == "error") as an error
  if printf '%s\n' "$out" | mc_output_has_error; then
    _printf "mc error payload (mc %s): %s\n" "$*" "$(printf '%s' "$out" | tr -d '\n' | head -c 300)" >&2
    return 1
  fi
  printf '%s\n' "$out"
}

# $1: S3 key relative to the bucket, used VERBATIM (manifest s3_key values).
# Sets global s3_presigned_url. Never recompose per-shard keys — the
# manifest-recorded key is the only source of truth.
get_s3_url_for_key() {
  local key="$1" result
  s3_presigned_url=""
  result=$(mc_json_safe share download --expire "$QDRANT_S3_LINK_EXPIRY_DURATION" \
    "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$key") || return 1
  s3_presigned_url=$(jq -r 'select(.status == "success") | .share' <<<"$result" | tail -n1)
  if [ -z "$s3_presigned_url" ] || [ "$s3_presigned_url" = "null" ]; then
    _printf "failed to presign key %s\n" "$key" >&2
    return 1
  fi
  return 0
}

# $1 peer uri (supported shapes: http://host:6335, http://host, host:6335, host)
# $2 target port. stdout: uri with its port replaced/appended.
# Pure function for unit testing; handles scheme-prefixed and bare-host formats.
# Note: bracketed IPv6 hosts (e.g., [::1]:6335) are NOT supported.
rewrite_peer_uri() {
  local uri="$1" port="$2" base scheme=""
  base="${uri#*://}"
  if [ "$base" != "$uri" ]; then
    scheme="${uri%%"$base"}"
  fi
  if [[ "$base" == *:* ]]; then
    base="${base%:*}"
  fi
  printf '%s%s:%s' "$scheme" "$base" "$port"
}

# Peer discovery for NEW paths, parameterized by discovery host:
# backup tasks pass "${source_hosts[0]}", restore tasks "${restore_hosts[0]}".
discover_peers() {
  local host="$1" result peers_list id uri
  # Reset peer map: stale entries from prior discovery must not leak
  peer_url_by_id=()
  if [ -z "$host" ]; then
    _printf "peer discovery host is empty — check QDRANT_SOURCE_HOSTS/QDRANT_RESTORE_HOSTS\n" >&2
    return 1
  fi
  result=$(_curl_rc GET "$host/cluster" --header "api-key: $QDRANT_API_KEY") || return 1
  # Guard jq parsing with error handling
  peers_list=$(jq -r '.result.peers // {} | to_entries[] | "\(.key) \(.value.uri)"' <<<"$result" 2>&1) || {
    _printf "discover_peers: unparseable cluster response\n" >&2
    return 1
  }
  while read -r id uri; do
    # Skip entries with empty id or uri
    if [ -z "$id" ]; then continue; fi
    if [ -z "$uri" ]; then continue; fi
    # assumes every peer serves REST on the same configured port (homogeneous StatefulSet)
    peer_url_by_id["$id"]=$(rewrite_peer_uri "$uri" "$QDRANT_HTTP_PORT")
    _printf "registered peer %s at %s\n" "$id" "${peer_url_by_id[$id]}"
  done <<< "$peers_list"
  if [ "${#peer_url_by_id[@]}" -eq 0 ]; then
    _printf "no peers discovered via %s\n" "$host" >&2
    return 1
  fi
  return 0
}

# $1 peer id → stdout URL. rc 1 with a clear message when unknown.
peer_url() {
  if [[ -z "${peer_url_by_id[$1]+x}" ]]; then
    _printf "unknown peer id %s (topology changed mid-run?)\n" "$1" >&2
    return 1
  fi
  printf '%s' "${peer_url_by_id[$1]}"
}

# Snapshot one shard on one peer with wait=true. rc 0 confirmed; rc 1 otherwise.
# Response fields land in globals shard_snap_name/_checksum (the response's
# own size field is no longer recorded — schema 2 takes the object size from
# the post-upload mc stat instead). Timeout or "accepted" is
# NOT success and is never recorded as done.
snapshot_one_shard() {
  local peer="$1" collection="$2" sid="$3" result status rc=0
  shard_snap_name=""; shard_snap_checksum=""
  result=$(_curl_rc POST "$peer/collections/$collection/shards/$sid/snapshots?wait=true" \
    --header "api-key: $QDRANT_API_KEY") || rc=$?
  if [ "$rc" -ne 0 ]; then
    _printf "[%s] shard %s snapshot request failed (rc=%s): %s\n" \
      "$peer" "$sid" "$rc" "${result//[[:space:]]/}"
    return 1
  fi
  status=$(qdrant_status_ok <<<"$result") || rc=$?
  if [ "$rc" -ne 0 ]; then
    _printf "[%s] shard %s snapshot not confirmed (status=%s)\n" "$peer" "$sid" "$status"
    return 1
  fi
  if ! shard_snap_name=$(jq -r '.result.name // empty' <<<"$result"); then
    _printf "[%s] shard %s snapshot: unparseable response\n" "$peer" "$sid"
    return 1
  fi
  shard_snap_checksum=$(jq -r '.result.checksum // ""' <<<"$result") || shard_snap_checksum=""
  if [ -z "$shard_snap_name" ] || [ "$shard_snap_name" = "null" ]; then
    _printf "[%s] shard %s snapshot returned no name\n" "$peer" "$sid"
    return 1
  fi
  return 0
}

# Back up one collection as one per-shard set. rc 0 manifest written / rc 1 failed.
# All failures are contained to this collection (one collection's failure never aborts the run).
backup_one_collection() {
  local collection="$1" host="${source_hosts[0]:-}"
  local info_file cluster_file shards_json="[]" sid pid peer key mfile=""
  info_file=$(mktemp -p "${TMPDIR:-.}"); cluster_file=$(mktemp -p "${TMPDIR:-.}")
  trap 'rm -f "$info_file" "$cluster_file" ${mfile:+"$mfile"}' RETURN

  if ! _curl_rc GET "$host/collections/$collection" \
      --header "api-key: $QDRANT_API_KEY" > "$info_file"; then
    _printf "[%s] SKIP %s: cannot fetch collection info\n" "$host" "$collection"
    return 1
  fi
  if ! _curl_rc GET "$host/collections/$collection/cluster" \
      --header "api-key: $QDRANT_API_KEY" > "$cluster_file"; then
    _printf "[%s] SKIP %s: cannot fetch cluster info\n" "$host" "$collection"
    return 1
  fi
  if ! check_preconditions "$info_file" "$cluster_file"; then
    _printf "SKIP %s: preconditions not met\n" "$collection"
    return 1
  fi

  local assignments ok=true
  if ! assignments=$(select_shard_peers < "$cluster_file"); then
    _printf "SKIP %s: shard peer selection failed\n" "$collection"
    return 1
  fi
  while IFS=',' read -r sid pid; do
    if [ -z "$sid" ]; then continue; fi
    if [ "$ok" != "true" ]; then break; fi
    peer=$(peer_url "$pid") || {
      _printf "SKIP %s: shard %s peer lookup failed\n" "$collection" "$sid"
      ok=false; break
    }
    _printf "[%s] %s shard %s: requesting snapshot\n" "$peer" "$collection" "$sid"
    local attempt=0 done_shard=false alt_pid max_attempts=2
    # A transport-timeout retry can orphan a completed-but-unrecorded snapshot in S3;
    # orphans are reclaimed by prune's sweep after the grace window.
    while [ "$attempt" -lt "$max_attempts" ] && [ "$done_shard" != "true" ]; do
      if snapshot_one_shard "$peer" "$collection" "$sid"; then done_shard=true; break; fi
      attempt=$((attempt + 1))
    done
    if [ "$done_shard" != "true" ]; then
      # one retry on a DIFFERENT Active replica peer
      alt_pid=$(jq -r --argjson sid "$sid" --argjson bad "$pid" "$JQ_NORMALIZE_REPLICAS"' |
        [ .[] | select(.shard_id == $sid and .state == "Active" and .peer_id != $bad) |
          .peer_id ] | sort | (.[0] // empty)' "$cluster_file") || alt_pid=""
      if [ -n "$alt_pid" ]; then
        peer=$(peer_url "$alt_pid") || {
          _printf "SKIP %s: shard %s alt-peer lookup failed\n" "$collection" "$sid"
          ok=false; break
        }
        if snapshot_one_shard "$peer" "$collection" "$sid"; then done_shard=true; pid="$alt_pid"; fi
      fi
    fi
    if [ "$done_shard" != "true" ]; then
      _printf "SKIP %s: shard %s could not be snapshotted after retries\n" "$collection" "$sid"
      ok=false; break
    fi
    key="snapshots/$collection/shards/$sid/$shard_snap_name"
    # mc stat the OBSERVED key — layout self-verification every run.
    # Schema 2 reuses this SAME stat to record the object's at-rest identity
    # (etag + size) for the restore pre-flight; an unreadable
    # etag/size fails the shard — a schema-2 manifest must never promise
    # integrity fields it cannot back.
    local stat_json etag_size obj_etag obj_size
    if ! stat_json=$(mc_json_safe stat "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$key"); then
      _printf "SKIP %s: shard %s snapshot %s not found at expected key %s\n" \
        "$collection" "$sid" "$shard_snap_name" "$key"
      ok=false; break
    fi
    if ! etag_size=$(parse_stat_etag_size <<<"$stat_json"); then
      _printf "SKIP %s: shard %s object %s carries no usable etag/size — cannot record integrity fields\n" \
        "$collection" "$sid" "$key"
      ok=false; break
    fi
    IFS=$'\t' read -r obj_etag obj_size <<<"$etag_size"
    # `size` is the S3 object size from the stat above (schema 2) — the
    # snapshot-create response's own size field is not the measurement the
    # restore-side stat comparison will make, so it is no longer recorded.
    if ! shards_json=$(jq --argjson sid "$sid" --argjson pid "$pid" \
        --arg name "$shard_snap_name" --arg key "$key" \
        --argjson size "$obj_size" --arg etag "$obj_etag" --arg sum "$shard_snap_checksum" \
        --arg at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '. + [{id: $sid, snapshot_name: $name, s3_key: $key, size: $size, etag: $etag,
               checksum: $sum, source_peer_id: $pid, created_at: $at}]' <<<"$shards_json"); then
      _printf "SKIP %s: shard %s manifest entry build failed\n" "$collection" "$sid"
      ok=false; break
    fi
  done <<<"$assignments"

  if [ "$ok" != "true" ]; then return 1; fi

  local aliases manifest qdrant_version pc pc_json
  qdrant_version=$(_curl_rc GET "$host/" --header "api-key: $QDRANT_API_KEY" \
      | jq -r '.version // "unknown"') || qdrant_version="unknown"
  if [ -z "$qdrant_version" ] || [ "$qdrant_version" = "unknown" ]; then
    _printf "WARNING: %s: cannot read Qdrant version — manifest records 'unknown' and the restore version gate will BLOCK this set\n" "$collection"
  fi
  if ! aliases=$(_curl_rc GET "$host/collections/$collection/aliases" \
      --header "api-key: $QDRANT_API_KEY" | jq -c '[.result.aliases[]?.alias_name]'); then
    _printf "WARNING: %s: alias fetch failed — manifest will carry aliases:[] and restore will NOT recreate aliases\n" "$collection"
    aliases="[]"
  fi
  if ! jq -e 'type == "array"' <<<"$aliases" >/dev/null; then aliases="[]"; fi
  # points_count freshness: re-read after the shard loop so the manifest reflects
  # a count closer to when the snapshots were actually taken (collection_config
  # below still carries the PRE-loop collection info — only points_count refreshes).
  pc=$(_curl_rc GET "$host/collections/$collection" --header "api-key: $QDRANT_API_KEY" \
      | jq -r '.result.points_count // 0') || pc=""
  pc_json="${pc:-null}"
  if ! manifest=$(jq -n --arg set "$BACKUP_SET_ID" --arg coll "$collection" \
      --arg ver "$qdrant_version" --arg ref "${GIT_REF:-unknown}" --argjson pc "$pc_json" \
      --slurpfile ci "$info_file" --argjson aliases "$aliases" --argjson shards "$shards_json" \
      '{set_id: $set, collection: $coll, qdrant_version: $ver, git_ref: $ref, pc: $pc,
        collection_info: $ci[0], aliases: $aliases, shards: $shards}' | build_manifest); then
    _printf "SKIP %s: manifest build failed\n" "$collection"
    return 1
  fi
  if ! validate_manifest <<<"$manifest"; then
    _printf "SKIP %s: manifest failed validation\n" "$collection"
    return 1
  fi
  mfile=$(mktemp -p "${TMPDIR:-.}")
  printf '%s\n' "$manifest" > "$mfile"
  # manifest LAST — the set exists only once this upload succeeds (atomicity: no manifest, no set)
  if ! mc --quiet cp "$mfile" \
      "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/backup_manifests/$collection/$BACKUP_SET_ID.json"; then
    _printf "SKIP %s: manifest upload failed\n" "$collection"
    return 1
  fi
  local count; count=$(jq 'length' <<<"$shards_json") || count="?"
  _printf "backup set %s complete for %s (%s shards)\n" \
    "$BACKUP_SET_ID" "$collection" "$count"
  return 0
}

# Backup orchestration task (dispatched by run() as `create_snap_shards`).
# Per-collection failures are contained and counted; only discovery/S3-setup
# failures — or a failure of the initial collection listing — abort the whole
# run (one collection's failure never aborts the run).
create_snap_shards_task() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      *) _printf "unknown create_snap_shards option: %s\n" "$1"; usage; exit 1 ;;
    esac
  done
  if ! [[ "$QDRANT_BACKUP_RETENTION_SETS" =~ ^[0-9]+$ ]]; then
    _printf "create_snap_shards: QDRANT_BACKUP_RETENTION_SETS must be a non-negative integer, got '%s'\n" \
      "$QDRANT_BACKUP_RETENTION_SETS"
    exit 1
  fi
  warn_ignored_legacy_env "backup"
  setup_s3_storage
  discover_peers "${source_hosts[0]:-}" || exit 1
  # pod-unique suffix (k8s sets HOSTNAME to the pod name); pid fallback for ad-hoc shells
  BACKUP_SET_ID="$(date -u '+%Y-%m-%dT%H-%M-%SZ')-${HOSTNAME:-p$$}"
  GIT_REF="${GIT_REF:-unknown}"
  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
    if ! ( get_collections ); then
      _printf "create_snap_shards: cannot fetch collections from %s — aborting before any backup work\n" \
        "${source_hosts[0]:-<unset>}"
      exit 1
    fi
  else
    local existing_count; existing_count=$(wc -l < "$QDRANT_COLLECTIONS_FILE" | tr -d ' ')
    _printf "WARNING: reusing existing %s file (%s collection(s)) — delete it or run 'reset' for a fresh fetch\n" \
      "$QDRANT_COLLECTIONS_FILE" "$existing_count"
  fi
  if [ ! -f "$QDRANT_COLLECTIONS_FILE" ]; then
    _printf "%s file not found — no collections available to back up; exiting cleanly\n" \
      "$QDRANT_COLLECTIONS_FILE"
    exit 0
  fi

  local ok_count=0 fail_count=0 line collection
  local ok_list; ok_list=$(mktemp -p "${TMPDIR:-.}")
  while IFS= read -r line; do
    collection="${line#*,}"
    if [ -z "$collection" ]; then continue; fi
    if backup_one_collection "$collection"; then
      ok_count=$((ok_count + 1))
      printf '%s\n' "$collection" >> "$ok_list"
    else
      fail_count=$((fail_count + 1))
    fi
  done < "$QDRANT_COLLECTIONS_FILE"
  _printf "per-shard backup summary: %d collection(s) ok, %d failed/skipped\n" \
    "$ok_count" "$fail_count"
  if [ $((ok_count + fail_count)) -eq 0 ]; then
    _printf "WARNING: no collections processed\n"
  fi

  if [ "$ok_count" -gt 0 ] && [ "$QDRANT_BACKUP_RETENTION_SETS" -gt 0 ]; then
    # prune_retention_all takes an optional collections-list file
    if ! prune_retention_all "$ok_list"; then
      _printf "WARNING: retention pass failed — bucket will grow; run prune_snap manually (backup itself succeeded)\n"
    fi
  fi
  rm -f "$ok_list"
  if [ "$fail_count" -gt 0 ]; then exit 1; fi
  exit 0
}

# List manifest set ids for a collection as a JSON array [{set_id}].
# rc NONZERO on listing or parse error (never treated as "no manifests") — a listing error must never read as an empty bucket.
list_manifest_sets() {
  local collection="$1" out
  out=$(mc_json_safe ls \
    "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/backup_manifests/$collection/") || return 1
  jq -c -s '[ .[] | select(.status == "success") | .key
              | sub("/$"; "") | split("/") | last
              | select(endswith(".json")) | {set_id: sub("\\.json$"; "")} ]' <<<"$out"
}

# Delete one whole set: manifest FIRST, then objects (restore can never
# select a set mid-deletion). Shard keys are
# extracted from the manifest BEFORE the manifest is deleted — an unparseable
# manifest aborts with ZERO deletions instead of deleting the manifest and
# stranding its objects with no record of what to look up.
delete_backup_set() {
  local collection="$1" set_id="$2" manifest keys key
  manifest=$(mc_json_safe cat \
    "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/backup_manifests/$collection/$set_id.json") || return 1
  if ! keys=$(jq -r '.shards[].s3_key' <<<"$manifest" 2>&1); then
    _printf "failed to parse manifest shards for %s/%s — aborting this set (nothing deleted)\n" \
      "$collection" "$set_id" >&2
    return 1
  fi
  _printf "deleting manifest for %s/%s\n" "$collection" "$set_id"
  if ! mc --quiet rm "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/backup_manifests/$collection/$set_id.json"; then
    _printf "failed to delete manifest for %s/%s — aborting this set\n" "$collection" "$set_id" >&2
    return 1
  fi
  while IFS= read -r key; do
    if [ -z "$key" ]; then continue; fi
    # SECURITY: never trust a manifest-recorded key blindly — a corrupted or
    # malicious manifest must not be able to delete anything outside this
    # collection's own shard prefix. Refusal is per-key containment, not
    # a whole-set abort: the manifest is already gone, so refusing just skips
    # this one dangerous line and continues with the set's other (valid) keys.
    case "$key" in
      "snapshots/$collection/shards/"*) : ;;
      *)
        _printf "REFUSING to delete out-of-scope key %s from manifest %s/%s\n" "$key" "$collection" "$set_id" >&2
        continue
        ;;
    esac
    _printf "deleting %s\n" "$key"
    # API delete would need collection+shard+name and the collection may be gone;
    # mc rm of the manifest-recorded key is authoritative: equivalent to the
    # shard-snapshot DELETE API on native S3 storage, and it also covers sets
    # whose collection no longer exists.
    if ! mc --quiet rm "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$key"; then
      _printf "warning: failed to delete %s (sweep will retry)\n" "$key" >&2
    fi
    # Qdrant may write a .checksum companion alongside a shard snapshot; best-
    # effort cleanup only — absence is normal (exact format verified at the
    # Task 11 spike), never treated as a failure.
    mc --quiet rm "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$key.checksum" 2>/dev/null || true
  done <<<"$keys"
  # Restore-state lifecycle: a pruned set's mirrored resume
  # history must not outlive the set it belongs to. Best-effort only — the
  # manifest and shard objects are already gone by this point regardless, so
  # a failure or absence here (the common case: most sets are never restore-
  # attempted) must never fail the prune.
  # Known, accepted, bounded gap: a restore
  # of THIS set running concurrently with this prune can re-create this exact
  # key via mirror_restore_state() immediately after this rm — its next
  # shard-recovery success re-mirrors unconditionally, with no knowledge the
  # set was just pruned. Nothing then reclaims it: the orphan sweep above only
  # lists snapshots/{c}/shards/, never restore_state/. Harmless in volume
  # (a few bytes, per occurrence) — deferred, not fixed here.
  _printf "cleaning up restore_state for pruned set %s/%s (best-effort; absence is normal)\n" \
    "$collection" "$set_id"
  mc --quiet rm "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/restore_state/$collection/$set_id.csv" \
    2>/dev/null || true
  _printf "pruned set %s of %s\n" "$set_id" "$collection"
  return 0
}

# Retention + fail-safe orphan sweep for one collection.
prune_one_collection() {
  local collection="$1" sets count keep="$QDRANT_BACKUP_RETENTION_SETS"
  sets=$(list_manifest_sets "$collection") || {
    _printf "prune aborted for %s: manifest listing failed\n" "$collection" >&2; return 1; }
  count=$(jq 'length' <<<"$sets") || {
    _printf "prune aborted for %s: manifest count computation failed\n" "$collection" >&2; return 1; }
  if [ "$count" -eq 0 ]; then
    _printf "prune: no manifests for %s — skipping (never sweep without manifests)\n" "$collection"
    return 0
  fi
  # QDRANT_BACKUP_RETENTION_SETS=0 clamps to 1 (hard floor: never delete
  # the last remaining set) — deliberately asymmetric with the legacy KEEP_RUNS gate
  # in prune_legacy_one, which REJECTS 0 outright instead of clamping it. Retention
  # 0 is an ordinary "minimum footprint" request; legacy KEEP_RUNS=0 would delete
  # every unverified legacy snapshot in one pass and is treated as operator error.
  # A non-numeric value is left UNCLAMPED here and is rejected by select_doomed_sets
  # below — never coerce a garbage config value into looking like a deliberate "1".
  # Operator note: create_snap_shards_task's automatic retention hook SKIPS calling
  # prune_retention_all entirely when QDRANT_BACKUP_RETENTION_SETS=0 (its own
  # `-gt 0` guard) — 0 there means "leave existing sets alone". A manual prune_snap
  # with the SAME value 0, by contrast, DOES run and clamps to 1 HERE — it keeps
  # only the newest 1 set and DELETES every other set. Same env var, different
  # task, different effect, by design — worth operator awareness.
  if [[ "$keep" =~ ^[0-9]+$ ]] && [ "$keep" -lt 1 ]; then keep=1; fi
  local doomed
  doomed=$(select_doomed_sets "$keep" <<<"$sets") || {
    _printf "prune aborted for %s: doomed-set computation failed (QDRANT_BACKUP_RETENTION_SETS='%s'?)\n" \
      "$collection" "$QDRANT_BACKUP_RETENTION_SETS" >&2; return 1; }
  local set_id drc=0
  while IFS= read -r set_id; do
    if [ -z "$set_id" ]; then continue; fi
    # Poison-manifest containment: one unreadable/corrupt doomed set must not
    # block pruning the OTHER, healthy doomed sets — attempt all, then decide.
    if ! delete_backup_set "$collection" "$set_id"; then
      _printf "WARNING: failed to prune set %s of %s — continuing with remaining doomed sets\n" \
        "$set_id" "$collection" >&2
      drc=1
    fi
  done <<<"$doomed"
  if [ "$drc" -ne 0 ]; then
    _printf "prune aborted for %s: retention had failures — skipping orphan sweep this pass (sweep only ever runs after a clean retention pass)\n" \
      "$collection" >&2
    return 1
  fi

  # --- orphan sweep with guards (fail-safe by construction) ---
  local objects refs obj_count del_count now grace
  objects=$(mc_json_safe ls -r \
    "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/snapshots/$collection/shards/") || {
    _printf "sweep aborted for %s: object listing failed\n" "$collection" >&2; return 1; }
  sets=$(list_manifest_sets "$collection") || return 1
  local set_ids
  set_ids=$(jq -r '.[].set_id' <<<"$sets") || {
    _printf "sweep aborted for %s: cannot enumerate manifest set ids\n" "$collection" >&2; return 1; }
  refs="[]"
  while IFS= read -r set_id; do
    if [ -z "$set_id" ]; then continue; fi
    local mfile_json mkeys
    mfile_json=$(mc_json_safe cat \
      "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/backup_manifests/$collection/$set_id.json") || {
      _printf "sweep aborted for %s: cannot re-read manifest %s\n" "$collection" "$set_id" >&2; return 1; }
    mkeys=$(jq -c '[.shards[].s3_key]' <<<"$mfile_json") || {
      _printf "sweep aborted for %s: cannot parse manifest %s\n" "$collection" "$set_id" >&2; return 1; }
    refs=$(jq --argjson new "$mkeys" '. + $new' <<<"$refs") || {
      _printf "sweep aborted for %s: reference-set merge failed\n" "$collection" >&2; return 1; }
  done <<<"$set_ids"

  grace="$QDRANT_SWEEP_GRACE_SECONDS"
  if ! [[ "$grace" =~ ^[0-9]+$ ]]; then
    _printf "sweep aborted for %s: QDRANT_SWEEP_GRACE_SECONDS must be a non-negative integer, got '%s'\n" \
      "$collection" "$grace" >&2
    return 1
  fi
  if [ "$grace" -lt 1 ]; then
    _printf "sweep aborted for %s: QDRANT_SWEEP_GRACE_SECONDS must be >= 1s; sweeping with no grace can delete an in-flight backup\n" \
      "$collection" >&2
    return 1
  fi
  if [ "$grace" -lt 3600 ]; then
    _printf "WARNING: QDRANT_SWEEP_GRACE_SECONDS=%s is under 1 hour for %s — orphan sweep may race with an in-flight backup\n" \
      "$grace" "$collection" >&2
  fi
  now=$(date -u +%s)

  # Candidates: unreferenced objects with their raw lastModified pre-converted to
  # epoch via a per-object try/catch — one object with an unparseable/missing date
  # must never abort (or corrupt) the whole collection's sweep computation.
  # The actual age DECISION always runs through the real
  # sweep_age_ok function below, never an inline jq comparison. A key whose
  # `.checksum`-stripped form IS referenced counts as referenced too — a shard
  # snapshot's checksum companion is never independently listed in a manifest,
  # so without this it would look orphaned even while its parent is kept.
  local candidates
  candidates=$(jq -r -s --argjson refs "$refs" --arg coll "$collection" '
    [ .[] | select(.status == "success")
      | {key: ("snapshots/" + $coll + "/shards/" + (.key | sub("^.*shards/"; ""))),
         raw: (.lastModified // "")}
      | select((.key | IN($refs[])) | not)
      | select(((.key | sub("\\.checksum$"; "")) | IN($refs[])) | not)
      | . + {epoch: (if .raw == "" then "" else
               (try ((.raw | sub("\\.[0-9]+"; "") | sub("\\+.*$"; "Z")
                 | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime) | tostring) catch "")
             end)} ]
    | .[] | [.key, .epoch] | @tsv' <<<"$objects") || {
    _printf "sweep aborted for %s: candidate computation failed\n" "$collection" >&2; return 1; }
  obj_count=$(jq -s '[ .[] | select(.status == "success") ] | length' <<<"$objects") || {
    _printf "sweep aborted for %s: object count computation failed\n" "$collection" >&2; return 1; }
  local unref_count
  unref_count=$(printf '%s\n' "$candidates" | grep -c . || true)

  local orphans="" key mtime_epoch
  while IFS=$'\t' read -r key mtime_epoch; do
    if [ -z "$key" ]; then continue; fi
    if [ -z "$mtime_epoch" ]; then
      _printf "WARNING: cannot parse lastModified for %s — treating as NOT eligible for sweep\n" "$key" >&2
      continue
    fi
    if sweep_age_ok "$now" "$mtime_epoch" "$grace"; then
      orphans+="$key"$'\n'
    fi
  done <<<"$candidates"

  del_count=$(printf '%s\n' "$orphans" | grep -c . || true)
  local deleted_count=0
  if [ "$del_count" -gt 0 ]; then
    check_sweep_safety "$(jq 'length' <<<"$sets")" "$obj_count" "$del_count" || return 1
    while IFS= read -r key; do
      if [ -z "$key" ]; then continue; fi
      _printf "sweeping orphan %s\n" "$key"
      if mc --quiet rm "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$key"; then
        deleted_count=$((deleted_count + 1))
      else
        _printf "warning: failed to delete orphan %s (will retry next pass)\n" "$key" >&2
      fi
    done <<<"$orphans"
  fi
  _printf "sweep: %s objects unreferenced, %s eligible after grace, %s deleted\n" \
    "$unref_count" "$del_count" "$deleted_count"
  return 0
}

# $1 optional collections-list file (bare "collection" lines OR "host,collection"
# lines — the ok_list Task 7's create_snap_shards_task writes uses bare names;
# $QDRANT_COLLECTIONS_FILE always has a comma). Defaults to $QDRANT_COLLECTIONS_FILE.
# Runs retention (never legacy) for every listed collection. rc 1 if ANY collection's
# prune_one_collection call fails — never masks a per-collection failure as success.
prune_retention_all() {
  local list_file="${1:-$QDRANT_COLLECTIONS_FILE}" line collection rc=0
  if [ ! -r "$list_file" ]; then
    _printf "prune_retention_all: cannot read collections list file %s\n" "$list_file" >&2
    return 1
  fi
  while IFS= read -r line; do
    if [ -z "$line" ]; then continue; fi
    case "$line" in
      *,*) collection="${line#*,}" ;;
      *) collection="$line" ;;
    esac
    if [ -z "$collection" ]; then continue; fi
    prune_one_collection "$collection" || rc=1
  done < "$list_file"
  return "$rc"
}

# Day-0 legacy prune: keep newest QDRANT_LEGACY_KEEP_RUNS per (collection, peer),
# delete only legacy-format keys directly under snapshots/{c}/. NEVER
# touches shards/ subpaths or backup_manifests/ keys — legacy objects only.
prune_legacy_one() {
  local collection="$1" listing names doomed name
  if ! legacy_keep_runs_ok "$QDRANT_LEGACY_KEEP_RUNS"; then
    _printf "legacy prune aborted for %s: QDRANT_LEGACY_KEEP_RUNS must be an integer >= 1, got '%s' (0 would delete every legacy snapshot; escalating to 1 must be an explicit operator decision, never a default)\n" \
      "$collection" "$QDRANT_LEGACY_KEEP_RUNS" >&2
    return 1
  fi
  listing=$(mc_json_safe ls \
    "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/snapshots/$collection/") || {
    _printf "legacy prune aborted for %s: listing failed\n" "$collection" >&2; return 1; }
  # only file objects directly under the collection prefix (no shards/, no dirs)
  if ! names=$(jq -r 'select(.status == "success") | select(.type != "folder") | .key
                 | split("/") | last' <<<"$listing" 2>&1); then
    _printf "legacy prune aborted for %s: listing parse failed: %s\n" "$collection" "$names" >&2
    return 1
  fi
  # blank lines dropped; .checksum companions dropped too — grouping them
  # alongside their .snapshot parent would just be noisy "SKIP unparseable"
  # spam (they never match group_legacy_snapshots' filename regex); each
  # doomed name's own companion is best-effort deleted below instead.
  names=$(printf '%s\n' "$names" | grep -vE '^$|\.checksum$' || true)
  if [ -z "$names" ]; then
    _printf "legacy prune: nothing under snapshots/%s/\n" "$collection"
    return 0
  fi
  if ! doomed=$(printf '%s\n' "$names" | group_legacy_snapshots "$QDRANT_LEGACY_KEEP_RUNS"); then
    _printf "legacy prune aborted for %s: grouping failed\n" "$collection" >&2
    return 1
  fi
  while IFS= read -r name; do
    if [ -z "$name" ]; then continue; fi
    _printf "legacy prune: deleting %s\n" "$name"
    mc --quiet rm "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/snapshots/$collection/$name" || return 1
    # Best-effort companion cleanup — absence is normal, never a failure.
    mc --quiet rm "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/snapshots/$collection/$name.checksum" 2>/dev/null || true
  done <<<"$doomed"
  return 0
}

# Retention task dispatched by run() as `prune_snap`; `--legacy` switches to the
# day-0 emergency unblock (prune_legacy_one) instead of normal per-set retention.
prune_snap_task() {
  local legacy=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --legacy) legacy=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) _printf "unknown prune_snap option: %s\n" "$1" >&2; exit 1 ;;
    esac
  done
  # Hoisted pre-flight (both branches): a garbage retention-sets value would
  # otherwise only surface deep inside prune_one_collection, after S3 setup
  # and a manifest listing already ran for the first collection.
  if ! [[ "$QDRANT_BACKUP_RETENTION_SETS" =~ ^[0-9]+$ ]]; then
    _printf "prune_snap: QDRANT_BACKUP_RETENTION_SETS must be a non-negative integer, got '%s'\n" \
      "$QDRANT_BACKUP_RETENTION_SETS" >&2
    exit 1
  fi
  if [ "$legacy" = "true" ]; then
    if ! legacy_keep_runs_ok "$QDRANT_LEGACY_KEEP_RUNS"; then
      _printf "prune_snap --legacy: QDRANT_LEGACY_KEEP_RUNS must be an integer >= 1, got '%s' — aborting before any listing (0 would delete every legacy snapshot; escalating to 1 must be an explicit operator decision)\n" \
        "$QDRANT_LEGACY_KEEP_RUNS" >&2
      exit 1
    fi
  fi
  warn_ignored_legacy_env "prune"
  setup_s3_storage
  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
    if [ -n "${source_hosts[0]:-}" ]; then
      if ! ( get_collections ); then
        _printf "prune_snap: cannot fetch collections from %s — aborting\n" \
          "${source_hosts[0]:-<unset>}" >&2
        exit 1
      fi
    else
      if ! ( fetch_collections_from_s3 ); then
        _printf "prune_snap: cannot fetch collections from s3 — aborting\n" >&2
        exit 1
      fi
    fi
  fi
  if [ ! -f "$QDRANT_COLLECTIONS_FILE" ]; then
    _printf "%s file not found — no collections available to prune; exiting cleanly\n" \
      "$QDRANT_COLLECTIONS_FILE"
    exit 0
  fi
  local rc=0
  if [ "$legacy" = "true" ]; then
    local line collection
    while IFS= read -r line; do
      if [ -z "$line" ]; then continue; fi
      case "$line" in
        *,*) collection="${line#*,}" ;;
        *) collection="$line" ;;
      esac
      if [ -z "$collection" ]; then continue; fi
      prune_legacy_one "$collection" || rc=1
    done < "$QDRANT_COLLECTIONS_FILE"
  else
    prune_retention_all "$QDRANT_COLLECTIONS_FILE" || rc=1
  fi
  exit "$rc"
}

# Legacy env knobs the per-shard tasks deliberately do NOT consume — a knob
# an operator set that silently does nothing violates the fail-loud bar, so
# each one is NAMED at per-shard task entry. Never changes behavior; rc 0
# always. $1 is the task family: "restore" adds the extra-hosts warning
# (backup legitimately reads multiple source hosts; restore is single-target
# by design — only the FIRST QDRANT_RESTORE_HOSTS entry is used).
warn_ignored_legacy_env() {
  if [ "${QDRANT_WAIT_ON_TASK:-true}" != "true" ]; then
    _printf "WARNING: QDRANT_WAIT_ON_TASK=%s is ignored by per-shard tasks (they always wait for task completion — 'accepted' is never success)\n" \
      "$QDRANT_WAIT_ON_TASK"
  fi
  if [ "${BACKUP_COLLECTION_ALIASES_ON_S3:-false}" = "true" ] \
      || [ "${QDRANT_COLLECTION_ALIASES_STABLE_FILE:-collection_aliases}" != "collection_aliases" ]; then
    _printf "WARNING: BACKUP_COLLECTION_ALIASES_ON_S3/QDRANT_COLLECTION_ALIASES_STABLE_FILE are ignored by per-shard tasks — aliases travel inside backup manifests\n"
  fi
  if [ "$1" = "restore" ] && [ "${#restore_hosts[@]}" -gt 1 ]; then
    _printf "WARNING: per-shard restore targets one cluster per run — %d extra host entries ignored; run once per cluster\n" \
      "$(( ${#restore_hosts[@]} - 1 ))"
  fi
  return 0
}

# $1 candidate value. rc 0 iff exactly "true" or "false" — restore's boolean
# env vars (QDRANT_RESTORE_FORCE, QDRANT_SKIP_VERSION_CHECK) are never coerced
# from a garbage value; anything else is always a clean abort.
bool_env_ok() {
  case "$1" in
    true|false) return 0 ;;
    *) return 1 ;;
  esac
}

# stdin: a Qdrant response JSON that might echo a presigned S3 URL back in a
# `.location` field. A presigned URL is a bearer credential —
# NEVER log a raw response that could carry one. stdout: the same JSON with
# `.location` replaced by a placeholder, or a safe fallback for unparseable
# (incl. empty) input. Never fails: always prints something safe to log.
# This is defense layer 1 (by FIELD NAME). It is NOT sufficient alone: a
# server could echo the URL back inside some OTHER field (e.g. error prose),
# which this cannot see since it only ever looks at `.location`. Callers that
# hold the raw URL value MUST also scrub by VALUE afterward (layer 2) —
# renamed from redact_location to redact_response because of this: it no
# longer only redacts one named field's worth of risk.
redact_response() {
  local out
  if out=$(jq -c 'if .location? then .location = "<redacted>" else . end' 2>/dev/null); then
    printf '%s' "${out:-<empty response>}"
    return 0
  fi
  printf '<unparseable response>'
}

# Pull the S3-mirrored resume history for (collection,set) if it exists.
# Attempts the fetch directly — no separate stat-then-cp probe, which
# had a silent-failure gap: if the object existed but the follow-up cp failed
# for any transient reason, the old code returned 0 with zero output, so
# resume being disabled was invisible. Now: on cp failure, probe the parent
# prefix to say WHICH case this is; never aborts (a missing/unfetchable
# resume state is never fatal to the restore, only to the resume optimization).
fetch_restore_state() {
  local collection="$1" set_id="$2"
  if mc cp "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/restore_state/$collection/$set_id.csv" \
      "$QDRANT_SHARD_RECOVERY_HISTORY_FILE.remote"; then
    touch "$QDRANT_SHARD_RECOVERY_HISTORY_FILE"
    cat "$QDRANT_SHARD_RECOVERY_HISTORY_FILE.remote" >> "$QDRANT_SHARD_RECOVERY_HISTORY_FILE"
    sort -u "$QDRANT_SHARD_RECOVERY_HISTORY_FILE" -o "$QDRANT_SHARD_RECOVERY_HISTORY_FILE"
    rm -f "$QDRANT_SHARD_RECOVERY_HISTORY_FILE.remote"
    return 0
  fi
  rm -f "$QDRANT_SHARD_RECOVERY_HISTORY_FILE.remote"
  # cp failed: distinguish "genuinely nothing there yet" (fresh start, info)
  # from "cannot tell" (listing itself fails, OR the key IS listed yet cp
  # still failed — an anomaly) — both of the latter get a loud WARNING, never
  # silence (resume being disabled must always be visible).
  local probe found=""
  if probe=$(mc_json_safe ls "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/restore_state/$collection/"); then
    found=$(jq -r --arg want "$set_id.csv" \
      'select(.status == "success" and (.key | split("/") | last) == $want) | .key' \
      <<<"$probe" 2>/dev/null) || found="unknown"
  else
    found="unknown"
  fi
  if [ -z "$found" ]; then
    _printf "no prior restore state for %s/%s (fresh start)\n" "$collection" "$set_id"
  else
    _printf "WARNING: prior restore state for %s/%s may exist but could not be fetched — resume disabled this run; already-recovered shards may be re-recovered (idempotent)\n" \
      "$collection" "$set_id" >&2
  fi
  return 0
}

# Mirror the resume history for (collection,set), ANY target, to S3 — CSV
# content, .csv extension (the file holds CSV lines
# `target,collection,set_id,shard,ok`, and restore_state/{c}/{set_id}.csv is
# the documented key shape).
# $QDRANT_SHARD_RECOVERY_HISTORY_FILE is SHARED across every collection/set
# this task processes in one run — scope the upload to just this
# (collection,set_id)'s own lines, REGARDLESS OF TARGET: fetch_restore_state
# merges OTHER targets' fetched lines for this same set into the shared local
# file before this runs (e.g. a canary target's durable history while a prod
# DR restore of the same set is running), and a target-scoped re-upload would
# silently erase them — that set's next canary resume would then find a
# non-empty target with no matching history and demand FORCE. Literal
# `grep -F` (never a regex): $collection/$set_id are not guaranteed
# metachar-free. The per-target resume CHECK stays scoped to
# (target,collection,set_id) — this widening is upload-side only.
mirror_restore_state() {
  local target="$1" collection="$2" set_id="$3" scoped=""
  trap 'rm -f ${scoped:+"$scoped"}' RETURN
  scoped=$(mktemp -p "${TMPDIR:-.}")
  grep -F ",$collection,$set_id," "$QDRANT_SHARD_RECOVERY_HISTORY_FILE" > "$scoped" || true
  mc --quiet cp "$scoped" \
    "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/restore_state/$collection/$set_id.csv" \
    || _printf "warning: could not mirror restore state to S3 for %s/%s\n" "$collection" "$set_id" >&2
}

# Purge the S3-mirrored durable resume state for a WHOLE collection, across
# every set (not just the currently-selected one) — FORCE
# and the absent-collection path both need this, because neither an
# about-to-be-recreated nor a currently-absent collection can have any
# actually-recovered shards; stale state for ANY prior set must not survive
# to suppress recovery. Extracted from the original FORCE-only inline block
# so both call sites share one implementation. `reason` is a short caller-supplied label (e.g. "FORCE",
# "absent-collection") purely for the log line — behavior is identical
# either way. Listing failure aborts (rc 1): a purge that cannot GUARANTEE a
# clean slate must not let the caller proceed.
purge_durable_restore_state() {
  local collection="$1" reason="$2"
  local state_list
  if ! state_list=$(mc_json_safe ls "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/restore_state/$collection/"); then
    return 1
  fi
  local state_names sname
  state_names=$(jq -r 'select(.status == "success" and .type == "file") | .key | split("/") | last' \
    <<<"$state_list" 2>/dev/null) || state_names=""
  while IFS= read -r sname; do
    if [ -z "$sname" ]; then continue; fi
    _printf "%s: purging durable resume state %s\n" "$reason" "restore_state/$collection/$sname"
    mc --quiet rm "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/restore_state/$collection/$sname" \
      || _printf "warning: failed to purge durable resume state restore_state/%s/%s (stale resume risk next run)\n" \
        "$collection" "$sname" >&2
  done <<<"$state_names"
  return 0
}

# Purge LOCAL (target,collection) resume-history lines, across every set —
# the local-file counterpart to purge_durable_restore_state above, needed
# for the SAME two call sites for the SAME reason. Extracted from the
# original FORCE-only inline block (unchanged behavior, just reusable).
# Never fails: a missing history file is not an error (nothing to purge).
purge_local_resume_history() {
  local target="$1" collection="$2"
  if [ ! -f "$QDRANT_SHARD_RECOVERY_HISTORY_FILE" ]; then return 0; fi
  local tmp="" hline
  trap 'rm -f ${tmp:+"$tmp"}' RETURN
  tmp=$(mktemp -p "${TMPDIR:-.}")
  while IFS= read -r hline; do
    case "$hline" in
      "$target,$collection,"*) : ;;
      *) printf '%s\n' "$hline" >> "$tmp" ;;
    esac
  done < "$QDRANT_SHARD_RECOVERY_HISTORY_FILE"
  mv "$tmp" "$QDRANT_SHARD_RECOVERY_HISTORY_FILE"
  tmp=""
}

# Recreate payload indexes from manifest payload_schema. Warn-only:
# caller treats a nonzero rc as non-fatal to the overall restore. Every Qdrant
# response is checked via qdrant_status_ok (accepted/error is never treated as
# a successfully-recreated index, same rule as everywhere else in this file).
recreate_payload_indexes() {
  local target="$1" collection="$2" manifest="$3" entry field schema rc=0 resp entries body
  entries=$(jq -c '(.collection_config.payload_schema // {}) | to_entries[]' <<<"$manifest" 2>/dev/null) || {
    _printf "warning: cannot read payload_schema from manifest for %s\n" "$collection" >&2
    return 1
  }
  while IFS= read -r entry; do
    if [ -z "$entry" ]; then continue; fi
    field=$(jq -r '.key' <<<"$entry" 2>/dev/null) || field=""
    schema=$(jq -c 'if .value.params != null then .value.params
                    else (.value.data_type | ascii_downcase) end' <<<"$entry" 2>/dev/null) || schema=""
    if [ -z "$field" ] || [ -z "$schema" ]; then
      _printf "warning: unreadable payload_schema entry for %s — skipping\n" "$collection" >&2
      rc=1
      continue
    fi
    # jq -n --arg/--argjson, never shell-interpolated into the JSON literal —
    # $field is manifest-sourced and could in principle contain a quote or
    # backslash; $schema is already-valid JSON (from the jq -c above), so it
    # is embedded as a JSON value (--argjson), not re-stringified (--arg).
    body=$(jq -n --arg field "$field" --argjson schema "$schema" \
      '{field_name: $field, field_schema: $schema}') || {
      _printf "warning: cannot build index request body for %s field %s\n" "$collection" "$field" >&2
      rc=1
      continue
    }
    resp=$(_curl_rc PUT "$target/collections/$collection/index?wait=true" \
      --header "api-key: $QDRANT_API_KEY" --header "Content-Type: application/json" \
      --data "$body") || rc=1
    qdrant_status_ok <<<"$resp" >/dev/null || rc=1
  done <<<"$entries"
  return "$rc"
}

# Recover one shard onto one target peer from a presigned S3 location, with
# wait=true. rc 0 only on a CONFIRMED "ok" status; "accepted", any non-2xx,
# and transport failure are all rc 1 and NEVER treated as success by the
# caller (same accepted-never-success rule as snapshot_one_shard).
# Any failure log redacts by FIELD (`.location`) AND by VALUE
# (the raw $location string, held here by the caller) — the by-field pass
# alone misses a server echoing the URL back inside some OTHER field (e.g.
# error prose in `.status.error`, which qdrant_status_ok would surface
# verbatim into $status too — both $resp_log and $status get the by-value
# scrub, since either can carry the raw URL into the log line).
recover_one_shard() {
  local peer="$1" collection="$2" sid="$3" location="$4" checksum="$5"
  local resp rc=0 status resp_log body
  # jq -n --arg, never shell-interpolated into the JSON literal (a presigned
  # URL or checksum could in principle contain a character JSON needs escaped).
  # v1.15.x never returns a checksum from snapshot-create (spike (a)); an
  # empty checksum sent literally is rejected — omit the key instead.
  body=$(jq -n --arg loc "$location" --arg sum "$checksum" \
    '{location: $loc, priority: "snapshot"} + (if $sum != "" then {checksum: $sum} else {} end)') || {
    _printf "restore failed for %s shard %s: cannot build recover request body\n" "$collection" "$sid" >&2
    return 1
  }
  # An inert integrity gate is a silent one —
  # say so every time it's inert, not just when something goes wrong.
  if [ -z "$checksum" ]; then
    _printf "[%s] %s shard %s: manifest carries no checksum — recovering WITHOUT integrity verification (v1.15.x never returns one)\n" "$peer" "$collection" "$sid"
  fi
  resp=$(_curl_rc PUT "$peer/collections/$collection/shards/$sid/snapshots/recover?wait=true" \
    --header "api-key: $QDRANT_API_KEY" --header "Content-Type: application/json" \
    --data "$body") || rc=$?
  if [ "$rc" -eq 0 ]; then
    status=$(qdrant_status_ok <<<"$resp") || rc=$?
  else
    status="curl-rc-$rc"
  fi
  if [ "$rc" -ne 0 ]; then
    resp_log=$(redact_response <<<"$resp")
    resp_log=${resp_log//"$location"/<redacted-url>}
    status=${status//"$location"/<redacted-url>}
    _printf "restore failed for %s shard %s (status=%s): %s\n" "$collection" "$sid" "$status" "$resp_log"
    return 1
  fi
  return 0
}

# $1 schema_version  $2 expected_etag  $3 expected_size  $4 observed_etag
# $5 observed_size ($4/$5 empty when the object is missing / its stat failed).
# stdout: one verdict token. rc 0 = proceed (match | v1-skip), rc 1 = failure:
#   v1-skip         schema 1 predates integrity fields — comparison does not apply
#   match           size and etag both equal
#   missing-object  no observed identity at all (object absent / stat failed)
#   size-mismatch   sizes differ (checked first — the truncation diagnosis)
#   etag-mismatch   etags differ as OPAQUE strings (multipart ETags are not
#                   MD5 — equality is the only claim this comparison makes)
#   invalid-input   unknown schema or an uncomparable field — fail closed
# This proves the object is UNCHANGED SINCE BACKUP (at-rest tamper/rot/
# truncation). It does NOT prove validity: if Qdrant wrote a corrupt object
# at backup time, its recorded ETag is the corrupt object's — the deep
# payload smoke at verification is the served-data counterpart (a pair,
# not alternatives).
check_object_integrity() {
  local schema="$1" want_etag="$2" want_size="$3" got_etag="$4" got_size="$5"
  if [ "$schema" = "1" ]; then
    printf 'v1-skip'
    return 0
  fi
  if [ "$schema" != "2" ]; then
    printf 'invalid-input'
    return 1
  fi
  if [ -z "$want_etag" ] || ! [[ "$want_size" =~ ^[0-9]+$ ]]; then
    printf 'invalid-input'
    return 1
  fi
  if [ -z "$got_etag" ] && [ -z "$got_size" ]; then
    printf 'missing-object'
    return 1
  fi
  if ! [[ "$got_size" =~ ^[0-9]+$ ]]; then
    printf 'invalid-input'
    return 1
  fi
  if [ "$got_size" -ne "$want_size" ]; then
    printf 'size-mismatch'
    return 1
  fi
  if [ "$got_etag" != "$want_etag" ]; then
    printf 'etag-mismatch'
    return 1
  fi
  printf 'match'
  return 0
}

# stdin: resume-history lines (target,collection,set_id,shard,ok).
# $1 target  $2 collection  $3 set_id  $4 force ("true"/"false")  $5..: shard
# ids. stdout: the ids still PENDING in this run, one per line, input order.
# Resume scoping (integrity wave): only pending shards get the
# object pre-flight — a shard already restored in a previous run must not
# block today's resume if its bucket object later rotted; that data is
# already in the cluster. Under force=true EVERY shard is pending: a FORCE
# run exists to re-recover from the bucket and purges the very history that
# would exempt, so nothing may dodge verification through it. Exact-line
# grep -qxF (never regex): $target/$collection may carry metacharacters.
select_pending_shards() {
  local target="$1" collection="$2" set_id="$3" force="$4"
  shift 4
  local history sid
  history=$(cat)
  if ! bool_env_ok "$force"; then
    _printf "select_pending_shards: force must be 'true' or 'false', got '%s'\n" "$force" >&2
    return 1
  fi
  for sid in "$@"; do
    if [ "$force" != "true" ] \
        && grep -qxF "$target,$collection,$set_id,$sid,ok" <<<"$history"; then
      continue
    fi
    printf '%s\n' "$sid"
  done
  return 0
}

# One shard object's at-rest identity vs its manifest entry. rc 0 only on a
# proceed verdict; every failure names collection, shard, key, set, and
# expected vs observed identity — callers abort BEFORE any destructive step.
# $1 schema  $2 collection  $3 set_id  $4 sid  $5 key  $6 want_etag  $7 want_size
verify_shard_object() {
  local schema="$1" collection="$2" set_id="$3" sid="$4" key="$5" want_etag="$6" want_size="$7"
  local stat_json got_etag="" got_size="" verdict vrc=0
  if stat_json=$(mc_json_safe stat "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$key"); then
    got_etag=$(jq -r '.etag // ""' <<<"$stat_json" 2>/dev/null) || got_etag=""
    got_size=$(jq -r 'if (.size | type) == "number" then .size else "" end' <<<"$stat_json" 2>/dev/null) || got_size=""
  fi
  verdict=$(check_object_integrity "$schema" "$want_etag" "$want_size" "$got_etag" "$got_size") || vrc=$?
  if [ "$vrc" -eq 0 ]; then
    return 0
  fi
  _printf "pre-flight: %s shard %s object %s in set %s failed integrity (%s): expected etag=%s size=%s, observed etag=%s size=%s\n" \
    "$collection" "$sid" "$key" "$set_id" "$verdict" \
    "$want_etag" "$want_size" "${got_etag:-<absent>}" "${got_size:-<absent>}"
  return 1
}

# Shard ids the last successful preflight_backup_set actually verified
# (space-separated). Consumed by restore_one_collection's in-loop integrity
# net — same globals-not-return-values convention as snapshot_one_shard.
PREFLIGHT_VERIFIED_SIDS=""

# Object pre-flight for ONE candidate set — runs during set selection,
# BEFORE the state gate and any destructive step (integrity wave).
# $1 target  $2 collection  $3 set_id  $4 manifest JSON. rc 0 pass / 1 fail
# (every failing object named). Fetches the candidate's durable resume state
# first (the state gate reuses the same merged local history file).
# Schema 1: existence + non-zero size for every shard object (correction H,
# unchanged) plus a loud flag — at-rest identity is not verifiable.
# Schema 2: verify_shard_object on the RESUME-SCOPED pending set only (see
# select_pending_shards for the scoping and FORCE rules).
preflight_backup_set() {
  local target="$1" collection="$2" set_id="$3" manifest="$4"
  local schema
  PREFLIGHT_VERIFIED_SIDS=""
  schema=$(jq -r '.schema_version' <<<"$manifest" 2>/dev/null) || schema=""
  fetch_restore_state "$collection" "$set_id"

  if [ "$schema" = "1" ]; then
    _printf "WARNING: manifest predates integrity fields (schema 1) — at-rest integrity pre-flight skipped (collection %s, set %s)\n" \
      "$collection" "$set_id"
    local key size stat_json missing=false s3_keys
    s3_keys=$(jq -r '.shards[].s3_key' <<<"$manifest" 2>/dev/null) || {
      _printf "pre-flight: cannot read shard keys from manifest %s for %s\n" "$set_id" "$collection" >&2
      return 1
    }
    while IFS= read -r key; do
      if [ -z "$key" ]; then continue; fi
      if ! stat_json=$(mc_json_safe stat "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/$key"); then
        _printf "pre-flight: missing object %s in set %s\n" "$key" "$set_id"
        missing=true
        continue
      fi
      size=$(jq -r '.size // 0' <<<"$stat_json" 2>/dev/null) || size=0
      if ! [[ "$size" =~ ^[0-9]+$ ]] || [ "$size" -eq 0 ]; then
        _printf "pre-flight: object %s in set %s has invalid or zero size (%s)\n" "$key" "$set_id" "$size"
        missing=true
      fi
    done <<<"$s3_keys"
    if [ "$missing" = "true" ]; then return 1; fi
    return 0
  fi

  if [ "$schema" != "2" ]; then
    # unreachable after validate_manifest — kept fail-closed regardless
    _printf "pre-flight: unsupported manifest schema '%s' for %s set %s\n" "$schema" "$collection" "$set_id" >&2
    return 1
  fi

  local shard_entries entry sid
  local sids=()
  local -A key_by_sid=() etag_by_sid=() size_by_sid=()
  shard_entries=$(jq -c '.shards[]' <<<"$manifest" 2>/dev/null) || {
    _printf "pre-flight: cannot read shard list from manifest %s for %s\n" "$set_id" "$collection" >&2
    return 1
  }
  while IFS= read -r entry; do
    if [ -z "$entry" ]; then continue; fi
    sid=$(jq -r '.id' <<<"$entry" 2>/dev/null) || sid=""
    # numeric only: sids feed URLs and the space-joined verified set — a
    # non-numeric id is a hostile/broken manifest, never worth guessing at
    if ! [[ "$sid" =~ ^[0-9]+$ ]]; then
      _printf "pre-flight: unreadable shard entry (id '%s') in manifest %s for %s\n" "$sid" "$set_id" "$collection" >&2
      return 1
    fi
    key_by_sid[$sid]=$(jq -r '.s3_key // ""' <<<"$entry" 2>/dev/null) || key_by_sid[$sid]=""
    etag_by_sid[$sid]=$(jq -r '.etag // ""' <<<"$entry" 2>/dev/null) || etag_by_sid[$sid]=""
    size_by_sid[$sid]=$(jq -r '.size // ""' <<<"$entry" 2>/dev/null) || size_by_sid[$sid]=""
    sids+=("$sid")
  done <<<"$shard_entries"

  local pending
  local pending_arr=()
  pending=$(select_pending_shards "$target" "$collection" "$set_id" "$QDRANT_RESTORE_FORCE" "${sids[@]}" \
    < "$QDRANT_SHARD_RECOVERY_HISTORY_FILE") || {
    _printf "pre-flight: pending-shard selection failed for %s set %s\n" "$collection" "$set_id" >&2
    return 1
  }
  while IFS= read -r sid; do
    if [ -z "$sid" ]; then continue; fi
    pending_arr+=("$sid")
  done <<<"$pending"
  if [ "${#pending_arr[@]}" -lt "${#sids[@]}" ]; then
    _printf "pre-flight: %s shard(s) already recovered for set %s — integrity check scoped to the %s still pending\n" \
      "$(( ${#sids[@]} - ${#pending_arr[@]} ))" "$set_id" "${#pending_arr[@]}"
  fi
  local failed=false
  for sid in "${pending_arr[@]}"; do
    if ! verify_shard_object "$schema" "$collection" "$set_id" "$sid" \
        "${key_by_sid[$sid]}" "${etag_by_sid[$sid]}" "${size_by_sid[$sid]}"; then
      failed=true
    fi
  done
  if [ "$failed" = "true" ]; then return 1; fi
  PREFLIGHT_VERIFIED_SIDS="${pending_arr[*]}"
  return 0
}

# Deep payload smoke scroll (integrity wave): bounded sampled
# scrolling — up to 3 pages x 100 points chained via next_page_offset, with
# with_payload: true on EVERY page. with_payload is load-bearing: R5b's
# corruption lived in payload storage (gridstore) and only a payload READ
# panics — a payload-less scroll can pass over broken storage. Goal:
# storage-level breakage detection, not per-point validation; the manifest
# etag/size pre-flight is the at-rest counterpart (a pair, not alternatives).
# $1 target  $2 collection  $3 expected_points (caller-confirmed numeric).
# rc 0 pass / rc 1 fail (the "verification failed" line printed here).
smoke_scroll_deep() {
  local target="$1" collection="$2" expected_points="$3"
  local pages=3 page_limit=100 page=1 offset='null' body resp scroll_n
  while [ "$page" -le "$pages" ]; do
    body=$(jq -n --argjson limit "$page_limit" --argjson off "$offset" \
      '{limit: $limit, with_payload: true}
       + (if $off == null then {} else {offset: $off} end)') || {
      _printf "verification failed for %s: cannot build smoke scroll body (page %s)\n" \
        "$collection" "$page" >&2
      return 1
    }
    resp=$(_curl_rc POST "$target/collections/$collection/points/scroll" \
      --header "api-key: $QDRANT_API_KEY" --header "Content-Type: application/json" \
      --data "$body") || {
      _printf "verification failed for %s: smoke scroll request failed (page %s)\n" \
        "$collection" "$page" >&2
      return 1
    }
    scroll_n=$(jq -r '.result.points | length' <<<"$resp" 2>/dev/null) || scroll_n=""
    if ! [[ "$scroll_n" =~ ^[0-9]+$ ]]; then
      _printf "verification failed for %s: smoke scroll response unparseable (page %s)\n" \
        "$collection" "$page" >&2
      return 1
    fi
    if [ "$page" -eq 1 ] && [ "$scroll_n" -lt 1 ] && [ "$expected_points" -gt 0 ]; then
      _printf "verification failed for %s: smoke scroll returned no points\n" "$collection" >&2
      return 1
    fi
    # `// null` also maps a JSON false to null — Qdrant offsets are numeric
    # or string point ids, never booleans, so nothing real is swallowed.
    offset=$(jq -c '.result.next_page_offset // null' <<<"$resp" 2>/dev/null) || offset='null'
    if [ -z "$offset" ] || [ "$offset" = "null" ]; then
      break   # collection exhausted before the page cap — sampled everything there is
    fi
    page=$((page + 1))
  done
  return 0
}

# Random-sample payload probes (round 2 — closes the T3 finding: the head
# scroll alone missed served corruption whose blast radius started past the
# sampled head, live-demonstrated on v1.15.1 with a re-stamped manifest). Up to
# QDRANT_VERIFY_SAMPLE_POINTS random points (default 300), batches of ≤100,
# via the Query API's `{"query": {"sample": "random"}}` — live-verified on
# v1.15.1, and random sampling exists since Qdrant 1.11 while this tool's
# floor is 1.15, so the probe is unconditional (no version fallback).
# with_payload: true on EVERY batch — only a payload READ touches gridstore,
# where R5b-class corruption lives. Honest register: a bounded random
# sample, never per-point validation — it catches a corrupt region covering
# fraction f of points with probability 1−(1−f)^N (≈95% at f=1% for N=300);
# small regions can escape. Fail-closed per batch: non-2xx (the panic/500
# path), unparseable response, or fewer points than min(limit,
# restored_points). The floor is the RESTORED count — the count the
# tolerance gate already certified — never the manifest count: a
# tolerance-accepted short restore (e.g. manifest=100, restored=99 within
# the default 1%) can only ever serve 99 sampled points, and flooring on
# the manifest would fail a GOOD restore (round-2 re-review LOW).
# A legitimately empty collection (expected 0) skips cleanly (loud).
# $1 target  $2 collection  $3 expected_points  $4 restored_points
# (both counts caller-confirmed numeric by the count gate).
# rc 0 pass / rc 1 fail (the "verification failed" line printed here).
smoke_sample_probes() {
  local target="$1" collection="$2" expected_points="$3" restored_points="$4"
  local sample="$QDRANT_VERIFY_SAMPLE_POINTS"
  if ! [[ "$restored_points" =~ ^[0-9]+$ ]]; then
    # unreachable after check_count_tolerance — kept fail-closed regardless
    _printf "verification failed for %s: sample probes need a numeric restored count, got '%s'\n" \
      "$collection" "$restored_points" >&2
    return 1
  fi
  if ! [[ "$sample" =~ ^[0-9]+$ ]]; then
    # unreachable after the task-entry gate — kept fail-closed regardless
    _printf "verification failed for %s: QDRANT_VERIFY_SAMPLE_POINTS must be a non-negative integer, got '%s'\n" \
      "$collection" "$sample" >&2
    return 1
  fi
  if [ "$sample" -eq 0 ]; then
    _printf "WARNING: QDRANT_VERIFY_SAMPLE_POINTS=0 — random-sample payload probes OFF for %s (served-data check reduced to the head scroll)\n" \
      "$collection"
    return 0
  fi
  if [ "$expected_points" -eq 0 ]; then
    _printf "restore of %s: expected 0 points — random-sample payload probes skipped\n" "$collection"
    return 0
  fi
  local batches batch=0 remaining="$sample" limit want body resp n
  batches=$(( (sample + 99) / 100 ))
  while [ "$batch" -lt "$batches" ]; do
    batch=$((batch + 1))
    limit="$remaining"
    if [ "$limit" -gt 100 ]; then limit=100; fi
    # live-verified: sample:random with limit > points_count returns exactly
    # every point, so min(limit, restored) is the fail-closed floor (restored,
    # not manifest — see the header: the tolerance gate owns the counts claim)
    want="$limit"
    if [ "$restored_points" -lt "$want" ]; then want="$restored_points"; fi
    body=$(jq -n --argjson limit "$limit" \
      '{query: {sample: "random"}, limit: $limit, with_payload: true}') || {
      _printf "verification failed for %s: cannot build sample probe body (batch %s/%s)\n" \
        "$collection" "$batch" "$batches" >&2
      return 1
    }
    resp=$(_curl_rc POST "$target/collections/$collection/points/query" \
      --header "api-key: $QDRANT_API_KEY" --header "Content-Type: application/json" \
      --data "$body") || {
      _printf "verification failed for %s: sample probe request failed (batch %s/%s)\n" \
        "$collection" "$batch" "$batches" >&2
      return 1
    }
    n=$(jq -r '.result.points | length' <<<"$resp" 2>/dev/null) || n=""
    if ! [[ "$n" =~ ^[0-9]+$ ]]; then
      _printf "verification failed for %s: sample probe response unparseable (batch %s/%s)\n" \
        "$collection" "$batch" "$batches" >&2
      return 1
    fi
    if [ "$n" -lt "$want" ]; then
      _printf "verification failed for %s: sample probe returned %s point(s), expected %s (batch %s/%s)\n" \
        "$collection" "$n" "$want" "$batch" "$batches" >&2
      return 1
    fi
    remaining=$((remaining - limit))
  done
  return 0
}

# Restore one collection from its selected manifest. rc 0 verified / rc 1
# failed. All failures are contained to this collection (same containment
# discipline as backup_one_collection).
restore_one_collection() {
  local collection="$1" target="${restore_hosts[0]}" filter="${QDRANT_SNAPSHOT_DATETIME_FILTER:-}"
  local sets set_id manifest live live_rc points

  sets=$(list_manifest_sets "$collection") || {
    _printf "restore aborted for %s: manifest listing failed\n" "$collection" >&2; return 1; }
  set_id=$(select_backup_set "$filter" <<<"$sets") || {
    _printf "restore aborted for %s: no matching backup set\n" "$collection" >&2; return 1; }

  # Candidate-selection loop (integrity wave): fetch + validate the
  # candidate's manifest, then object-pre-flight it (existence + non-zero
  # size; schema 2 adds the etag/size identity comparison, resume-scoped —
  # see preflight_backup_set) BEFORE committing to the set, the state gate,
  # and any destructive step. On failure without a filter, fall back one set
  # at a time with a loud warning naming BOTH sets — every fallback candidate
  # gets the SAME pre-flight before being committed to. With a filter, abort — a filtered
  # restore never silently substitutes another set ("the operator
  # did not choose it"); pinning a known-good set stays the documented
  # escape hatch (RUNBOOK "Set selection semantics").
  # touch first: fetch_restore_state (inside preflight_backup_set) only
  # creates the history file itself on the cp-success path; the resumable
  # check and the per-shard skip check below need it to exist either way.
  touch "$QDRANT_SHARD_RECOVERY_HISTORY_FILE"
  local prev_bad manifest_schema
  while true; do
    manifest=$(mc_json_safe cat \
      "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/backup_manifests/$collection/$set_id.json") || return 1
    if ! validate_manifest <<<"$manifest"; then
      _printf "restore aborted for %s: manifest %s failed validation\n" "$collection" "$set_id" >&2
      return 1
    fi
    if preflight_backup_set "$target" "$collection" "$set_id" "$manifest"; then
      break
    fi
    if [ -n "$filter" ]; then
      _printf "restore aborted for %s: filtered set %s is incomplete\n" "$collection" "$set_id" >&2
      return 1
    fi
    prev_bad="$set_id"
    sets=$(jq -c --arg bad "$set_id" 'map(select(.set_id != $bad))' <<<"$sets" 2>/dev/null) || {
      _printf "restore aborted for %s: cannot compute fallback set list\n" "$collection" >&2
      return 1
    }
    set_id=$(select_backup_set "" <<<"$sets") || {
      _printf "restore aborted for %s: set %s incomplete and no older set available\n" \
        "$collection" "$prev_bad" >&2
      return 1
    }
    _printf "WARNING: set %s incomplete for %s — falling back to older set %s\n" \
      "$prev_bad" "$collection" "$set_id"
  done
  manifest_schema=$(jq -r '.schema_version' <<<"$manifest" 2>/dev/null) || manifest_schema=""

  # Resume state was fetched per candidate inside preflight_backup_set,
  # BEFORE the state gate — case 2 below needs to know
  # whether this target already carries progress for the COMMITTED set
  # before it can decide whether a non-empty target is resumable.
  local resumable=false
  # $target-scoped (not just collection+set): deliberately MORE specific than
  # mirror_restore_state's own upload filter, which is (collection,set_id)
  # only, ANY target (widened so one target's mirror never erases another's durable history
  # for the same set — e.g. quarterly canary vs. prod DR of the same set).
  # Precisely BECAUSE the upload is no longer target-scoped,
  # restore_state/{c}/{set}.csv can legitimately hold another target's lines
  # too — an unscoped CHECK here would then let target A's mirrored history
  # admit case 2 (skip-create) on target B's unrelated non-empty collection,
  # recovering shards into data nobody verified belongs to this restore,
  # without FORCE. Matches the $target-first idiom already used by the exact
  # per-shard skip check below, which also stays target-scoped.
  if grep -qF "$target,$collection,$set_id," "$QDRANT_SHARD_RECOVERY_HISTORY_FILE" 2>/dev/null; then
    resumable=true
  fi

  # version gate — mirrors backup_one_collection's own version probe
  # exactly: api-key header, "unknown" on any failure, NO numeric fallback
  # (e.g. "0.0.0") that could accidentally satisfy or defeat the gate either
  # way. check_version_gate fails closed on a non-numeric version by design;
  # QDRANT_SKIP_VERSION_CHECK is the documented, explicit override.
  local target_ver manifest_ver
  target_ver=$(_curl_rc GET "$target/" --header "api-key: $QDRANT_API_KEY" \
      | jq -r '.version // "unknown"') || target_ver="unknown"
  if [ -z "$target_ver" ] || [ "$target_ver" = "unknown" ]; then
    _printf "WARNING: %s: cannot read target Qdrant version at %s — version gate evaluates 'unknown' and fails closed unless QDRANT_SKIP_VERSION_CHECK=true\n" \
      "$collection" "$target"
    target_ver="unknown"
  fi
  manifest_ver=$(jq -r '.qdrant_version' <<<"$manifest" 2>/dev/null) || manifest_ver=""
  check_version_gate "$manifest_ver" "$target_ver" "$QDRANT_SKIP_VERSION_CHECK" || {
    _printf "restore aborted for %s: version gate (manifest=%s target=%s)\n" \
      "$collection" "$manifest_ver" "$target_ver" >&2
    return 1
  }

  # capacity gate — deliberately BEFORE the state gate below: the state
  # gate's FORCE branch DELETEs an existing collection. Capacity must be
  # confirmed sufficient before any mutation, never discovered insufficient
  # after one already happened (a bug in the original draft: the capacity
  # check was placed textually after the FORCE delete — fixed here).
  local wcf rf
  wcf=$(jq -r '.collection_config.config.params.write_consistency_factor // 1' <<<"$manifest" 2>/dev/null) || wcf=""
  rf=$(jq -r '.collection_config.config.params.replication_factor // 1' <<<"$manifest" 2>/dev/null) || rf=""
  check_capacity_gate "$wcf" "$rf" "${#peer_url_by_id[@]}" || {
    _printf "restore aborted for %s: capacity gate\n" "$collection" >&2
    return 1
  }

  # collection state gate (three cases exactly). _curl_rc
  # rc 2 means "transport failure, state truly unknown" — never treated as
  # absent; a connectivity blip must never be treated as "collection absent,
  # safe to create". rc 1 means "reached the target, got a non-2xx" —
  # usually a 404 (genuinely absent), but ANY non-2xx (403, 500, a
  # misconfigured api-key...) collapses to the same branch below. That is a
  # deliberate, disclosed simplification, not a claim that rc 1 proves
  # absence: every non-2xx is treated the same ("proceed toward create"),
  # and a real underlying problem (auth, server health) is not silently
  # masked — it resurfaces one step later as a loud create-PUT failure. One
  # added cost of the pre-gate resume fetch: the create path below now also purges
  # durable/local resume state for this collection, so a transient rc 1 from
  # an auth/server blip would purge resume state it didn't need to — a
  # bounded, recoverable cost (idempotent re-recovery next run), never data
  # loss.
  live_rc=0
  live=$(_curl_rc GET "$target/collections/$collection" --header "api-key: $QDRANT_API_KEY") || live_rc=$?
  if [ "$live_rc" -eq 2 ]; then
    _printf "restore aborted for %s: cannot determine target collection state (transport error reaching %s)\n" \
      "$collection" "$target" >&2
    return 1
  fi
  if [ "$live_rc" -eq 0 ]; then
    # points_count fail-closed: absent/non-numeric becomes
    # "unknown", which never equals "0" and is rejected by the numeric guard
    # below either way — always falls to case 3 (abort/FORCE), never case 2,
    # even if resumable happens to be true (resume history alone is not
    # enough if we cannot even confirm the target's own reported state).
    points=$(jq -r '.result.points_count // "unknown"' <<<"$live" 2>/dev/null) || points="unknown"
    if ! [[ "$points" =~ ^[0-9]+$ ]]; then points="unknown"; fi
    local compat_rc=0
    # Not separately guarded: if $live/$manifest were somehow unparseable here
    # (shouldn't happen — live came from a 2xx _curl_rc response, manifest
    # already passed validate_manifest), the leading `jq -n --argjson` would
    # fail and, under pipefail, so would this whole pipeline; compare_collection_config
    # itself degrades an empty/unparseable stdin to rc 6 (verified: its own
    # `ok` stays unset/not "true"), never a crash — so this is safe by
    # construction either way, just belt-and-suspenders via the `|| compat_rc=$?`.
    jq -n --argjson l "$live" --argjson m "$manifest" '{live: $l, manifest: $m}' \
      | compare_collection_config || compat_rc=$?
    # Case 2: compatible AND (empty OR set-scoped resumable).
    if [[ "$points" =~ ^[0-9]+$ ]] && { [ "$points" = "0" ] || [ "$resumable" = "true" ]; } \
        && [ "$compat_rc" -eq 0 ]; then
      if [ "$points" = "0" ]; then
        _printf "target %s exists empty+compatible — resuming without create\n" "$collection"
      else
        _printf "target %s exists non-empty (points=%s) but has matching resume history for set %s and compatible config — resuming without create\n" \
          "$collection" "$points" "$set_id"
      fi
    elif [ "$QDRANT_RESTORE_FORCE" = "true" ]; then
      _printf "FORCE: deleting %s on target and starting clean (history purged)\n" "$collection"
      _curl_rc DELETE "$target/collections/$collection?wait=true" \
        --header "api-key: $QDRANT_API_KEY" > /dev/null || {
        _printf "restore aborted for %s: FORCE delete failed\n" "$collection" >&2
        return 1
      }
      # FORCE never overwrites in place: purge (target,collection) resume
      # state — local AND durable — so a fresh restore never inherits
      # another point-in-time's progress. Extracted into
      # shared helpers (purge_local_resume_history / purge_durable_restore_
      # state) since the absent-collection path below needs the identical
      # purge for the identical reason: neither a
      # just-deleted-and-about-to-be-recreated nor a currently-absent
      # collection can have any actually-recovered shards.
      purge_local_resume_history "$target" "$collection"
      purge_durable_restore_state "$collection" "FORCE" || {
        _printf "restore aborted for %s: FORCE could not verify/purge durable resume state\n" "$collection" >&2
        return 1
      }
      live_rc=1
    else
      _printf "restore aborted for %s: target exists (points=%s, compat_rc=%s) and QDRANT_RESTORE_FORCE!=true\n" \
        "$collection" "$points" "$compat_rc" >&2
      return 1
    fi
  fi

  if [ "$live_rc" -ne 0 ]; then
    # M2: a collection about to be (re)created cannot have any actually-
    # recovered shards — purge local+durable resume state here too,
    # unconditionally. Idempotent/cheap when FORCE already purged moments
    # ago (an empty listing, zero log lines) — and the ONLY place this runs
    # at all when the collection was absent from the very start (case 1)
    # rather than reached via FORCE. Without this, fetch_restore_state's
    # earlier (pre-gate) import could carry stale "already recovered" lines
    # into a brand-new collection's per-shard loop, silently skipping real
    # recovery — the exact bug class the FORCE-path purge closed,
    # now also closed for the natural-absence case.
    purge_local_resume_history "$target" "$collection"
    purge_durable_restore_state "$collection" "absent-collection" || {
      _printf "restore aborted for %s: could not verify/purge durable resume state for absent collection\n" \
        "$collection" >&2
      return 1
    }
    local body
    body=$(jq '{result: .collection_config}' <<<"$manifest" | map_config_get_to_put) || {
      _printf "restore aborted for %s: collection config mapping failed\n" "$collection" >&2
      return 1
    }
    _curl_rc PUT "$target/collections/$collection?wait=true" \
      --header "api-key: $QDRANT_API_KEY" --header "Content-Type: application/json" \
      --data "$body" > /dev/null || {
      _printf "restore aborted for %s: collection create failed\n" "$collection" >&2
      return 1
    }
  fi

  recreate_payload_indexes "$target" "$collection" "$manifest" \
    || _printf "warning: payload index recreation had failures for %s\n" "$collection" >&2

  # per-shard recovery — resume state was already fetched above,
  # before the gate; nothing left to fetch here.
  local target_cluster shard_entries entry sid pid peer sum key want_etag want_size
  target_cluster=$(_curl_rc GET "$target/collections/$collection/cluster" \
    --header "api-key: $QDRANT_API_KEY") || {
    _printf "restore aborted for %s: cannot read target cluster info\n" "$collection" >&2
    return 1
  }
  # One shard->peer placement pass for the whole collection, not a
  # per-shard live jq pick: the old inline pick always took `sort | .[0]`
  # (the numerically LOWEST Active peer id) for every shard, so a 12-shard
  # collection funneled every download through one peer instead of
  # spreading across the replica set. select_shard_peers already existed
  # (used by check_preconditions) and already round-robins per shard index
  # — reusing it here fixes the funnel and removes the duplicated jq.
  local -A shard_peer=()
  local speer_out speer_sid speer_pid
  speer_out=$(select_shard_peers <<<"$target_cluster") || speer_out=""
  while IFS=',' read -r speer_sid speer_pid; do
    if [ -z "$speer_sid" ]; then continue; fi
    shard_peer["$speer_sid"]="$speer_pid"
  done <<<"$speer_out"
  shard_entries=$(jq -c '.shards[]' <<<"$manifest" 2>/dev/null) || {
    _printf "restore aborted for %s: cannot read shard list from manifest\n" "$collection" >&2
    return 1
  }
  while IFS= read -r entry; do
    if [ -z "$entry" ]; then continue; fi
    sid=$(jq -r '.id' <<<"$entry" 2>/dev/null) || sid=""
    key=$(jq -r '.s3_key' <<<"$entry" 2>/dev/null) || key=""
    sum=$(jq -r '.checksum // ""' <<<"$entry" 2>/dev/null) || sum=""
    if [ -z "$sid" ] || [ -z "$key" ]; then
      _printf "restore failed for %s: unreadable shard entry in manifest %s\n" "$collection" "$set_id" >&2
      return 1
    fi
    # set-scoped resume only: a literal (non-regex) exact-line match — $target
    # may contain characters that are regex metacharacters (e.g. `.`).
    if grep -qxF "$target,$collection,$set_id,$sid,ok" "$QDRANT_SHARD_RECOVERY_HISTORY_FILE"; then
      _printf "shard %s already recovered for set %s — skipping\n" "$sid" "$set_id"
      continue
    fi
    # SECURITY: never presign a manifest-recorded key outside this collection's
    # own shard prefix (same defense-in-depth as Task 8's delete-path M2) —
    # BEFORE presigning. A restore needs every shard, so refusal fails the
    # WHOLE collection (unlike Task 8's per-key delete containment, where the
    # set's other valid keys could still be cleaned up independently).
    case "$key" in
      "snapshots/$collection/shards/"*) : ;;
      *)
        _printf "REFUSING to restore out-of-scope key %s for %s shard %s\n" "$key" "$collection" "$sid" >&2
        return 1
        ;;
    esac
    # Integrity net (integrity wave): the selection-time pre-flight
    # exempts a shard only on its resume history, and the FORCE / absent-
    # collection paths purge that history AFTER selection — so a shard can
    # reach this loop with its exemption expired. Never hand Qdrant an
    # object this run never verified; no-op for every shard the pre-flight
    # already covered.
    if [ "$manifest_schema" = "2" ]; then
      case " ${PREFLIGHT_VERIFIED_SIDS:-} " in
        *" $sid "*) : ;;
        *)
          want_etag=$(jq -r '.etag // ""' <<<"$entry" 2>/dev/null) || want_etag=""
          want_size=$(jq -r '.size // ""' <<<"$entry" 2>/dev/null) || want_size=""
          if ! verify_shard_object "$manifest_schema" "$collection" "$set_id" "$sid" \
              "$key" "$want_etag" "$want_size"; then
            return 1
          fi
          ;;
      esac
    fi
    pid="${shard_peer[$sid]:-}"
    if [ -z "$pid" ]; then
      _printf "restore failed for %s: no Active target replica placement for shard %s\n" "$collection" "$sid" >&2
      return 1
    fi
    peer=$(peer_url "$pid") || return 1
    get_s3_url_for_key "$key" || return 1
    if ! recover_one_shard "$peer" "$collection" "$sid" "$s3_presigned_url" "$sum"; then
      return 1   # accepted/timeout is NOT success and is never recorded
    fi
    printf '%s,%s,%s,%s,ok\n' "$target" "$collection" "$set_id" "$sid" \
      >> "$QDRANT_SHARD_RECOVERY_HISTORY_FILE"
    mirror_restore_state "$target" "$collection" "$set_id"
  done <<<"$shard_entries"

  # aliases from the MANIFEST, per-alias helper reuse.
  # recovered_colla_count / failed_recovered_colla_count are legacy globals
  # that recover_collection_alias (frozen legacy code) increments directly —
  # it takes no counter arguments; left global to match that legacy contract.
  local alias aliases_list alias_owner_resp owner
  recovered_colla_count=0; failed_recovered_colla_count=0
  touch "$QDRANT_ALIAS_RECOVERY_HISTORY_FILE"
  aliases_list=$(jq -r '.aliases[]?' <<<"$manifest" 2>/dev/null) || aliases_list=""
  # Alias theft guard: recover_collection_alias (legacy) would happily
  # repoint a LIVE alias currently owned by some OTHER collection — that is
  # only ever safe under an explicit FORCE, same authorization the state
  # gate already requires for a destructive collection overwrite. One GET
  # for the whole alias table (not per-alias — /aliases already lists all of
  # them). A fetch failure fails toward restoring (warn, then attempt every
  # alias anyway) rather than blocking the whole collection on a guard that
  # itself couldn't run.
  if ! alias_owner_resp=$(_curl_rc GET "$target/aliases" --header "api-key: $QDRANT_API_KEY"); then
    _printf "warning: cannot read existing aliases on %s — proceeding without the alias-theft guard (fail toward restoring)\n" \
      "$target" >&2
    alias_owner_resp=""
  fi
  while IFS= read -r alias; do
    if [ -z "$alias" ]; then continue; fi
    owner=""
    if [ -n "$alias_owner_resp" ]; then
      owner=$(jq -r --arg a "$alias" \
        '(.result.aliases // [])[] | select(.alias_name == $a) | .collection_name' \
        <<<"$alias_owner_resp" 2>/dev/null) || owner=""
    fi
    if [ -n "$owner" ] && [ "$owner" != "$collection" ] && [ "$QDRANT_RESTORE_FORCE" != "true" ]; then
      _printf "REFUSING to repoint live alias %s from %s to %s (set QDRANT_RESTORE_FORCE=true to override)\n" \
        "$alias" "$owner" "$collection" >&2
      failed_recovered_colla_count=$((failed_recovered_colla_count + 1))
      continue
    fi
    recover_collection_alias "$collection" "$alias" "$target"
  done <<<"$aliases_list"
  # Aliases are part of the restored contract, not a side effect of it
  # ("exit code reflects verification" applies here too) — a
  # collection whose data verifies but whose aliases didn't recover is not
  # a fully successful restore. Checked here, enforced at the very end
  # (after the rest of verification still runs, so its own pass/fail is
  # never masked by an unrelated alias problem).
  local aliases_ok=true
  if [ "$failed_recovered_colla_count" -gt 0 ]; then
    _printf "WARNING: %d/%d collection alias(es) failed to recover for %s\n" \
      "$failed_recovered_colla_count" "$((recovered_colla_count + failed_recovered_colla_count))" "$collection" >&2
    aliases_ok=false
  fi

  # verification — the exit code reflects it. Poll budget is
  # configurable (the old hardcoded 30 tries * 2s = 60s cap was too tight for
  # a real green-status wait on larger shard transfers).
  local green_timeout="$QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS" \
    green_interval="$QDRANT_VERIFY_POLL_INTERVAL_SECONDS" max_tries
  max_tries=$((green_timeout / green_interval))
  if [ "$max_tries" -lt 1 ]; then max_tries=1; fi
  local expected_points restored_points status_now tries=0
  expected_points=$(jq -r '.points_count' <<<"$manifest" 2>/dev/null) || expected_points=""
  while [ "$tries" -lt "$max_tries" ]; do
    live=$(_curl_rc GET "$target/collections/$collection" --header "api-key: $QDRANT_API_KEY") || live="{}"
    status_now=$(jq -r '.result.status // "unknown"' <<<"$live" 2>/dev/null) || status_now="unknown"
    if [ "$status_now" = "green" ]; then break; fi
    tries=$((tries + 1))
    if [ "$tries" -lt "$max_tries" ]; then sleep "$green_interval"; fi
  done
  if [ "$status_now" != "green" ]; then
    _printf "verification failed for %s: status=%s after waiting up to %ss\n" \
      "$collection" "$status_now" "$green_timeout" >&2
    return 1
  fi
  restored_points=$(jq -r '.result.points_count // 0' <<<"$live" 2>/dev/null) || restored_points=""
  # green status precedes count convergence by a beat (observed live:
  # recoveries and first green land in the same second); re-poll the count
  # within the budget instead of failing on a racing first read.
  local count_tries=0 count_max_tries=$((max_tries - tries)) count_ok=false
  while [ "$count_tries" -lt "$count_max_tries" ]; do
    if check_count_tolerance "$expected_points" "$restored_points" "$QDRANT_VERIFY_TOLERANCE_PCT"; then
      count_ok=true
      break
    fi
    count_tries=$((count_tries + 1))
    if [ "$count_tries" -lt "$count_max_tries" ]; then
      sleep "$green_interval"
      live=$(_curl_rc GET "$target/collections/$collection" --header "api-key: $QDRANT_API_KEY") || live="{}"
      restored_points=$(jq -r '.result.points_count // 0' <<<"$live" 2>/dev/null) || restored_points=""
    fi
  done
  if [ "$count_ok" != "true" ]; then
    _printf "verification failed for %s: point count outside tolerance\n" "$collection" >&2
    return 1
  fi
  target_cluster=$(_curl_rc GET "$target/collections/$collection/cluster" \
    --header "api-key: $QDRANT_API_KEY") || {
    _printf "verification failed for %s: cannot read target cluster info\n" "$collection" >&2
    return 1
  }
  local expected_rf peers_n
  expected_rf=$(jq -r '.collection_config.config.params.replication_factor // 1' <<<"$manifest" 2>/dev/null) || expected_rf=""
  # Discovered peer count may include unhealthy/unreachable peers — discover_peers
  # only confirms cluster membership, not liveness — so expected_rf can be
  # optimistic and verification may then report under-replication for a peer
  # that's actually down. That is correct, fail-toward-noticing behavior:
  # an operator should see the shortfall, never have it silently hidden.
  peers_n=${#peer_url_by_id[@]}
  if [[ "$expected_rf" =~ ^[0-9]+$ ]] && [ "$peers_n" -lt "$expected_rf" ]; then expected_rf="$peers_n"; fi
  # Retried within the same poll budget as the green-status wait above:
  # a surplus Partial replica or a slow empty-sibling fill is transient by
  # nature (qdrant#7851) — re-fetch cluster info and
  # re-check rather than hard-failing on the first snapshot of in-flight
  # replication.
  local replica_tries=0 replica_ok=false
  while [ "$replica_tries" -lt "$max_tries" ]; do
    if check_replica_sets "$expected_rf" <<<"$target_cluster"; then
      replica_ok=true
      break
    fi
    replica_tries=$((replica_tries + 1))
    if [ "$replica_tries" -lt "$max_tries" ]; then
      sleep "$green_interval"
      target_cluster=$(_curl_rc GET "$target/collections/$collection/cluster" \
        --header "api-key: $QDRANT_API_KEY") || {
        _printf "verification failed for %s: cannot read target cluster info\n" "$collection" >&2
        return 1
      }
    fi
  done
  if [ "$replica_ok" != "true" ]; then
    _printf "verification failed for %s: replica set check did not pass within %ss\n" \
      "$collection" "$green_timeout" >&2
    return 1
  fi
  # smoke: deep payload scroll (integrity wave) — replaces the limit-1 scroll
  # R5b sailed past. expected_points is already confirmed numeric here —
  # check_count_tolerance above would have returned 1 otherwise.
  local resp
  smoke_scroll_deep "$target" "$collection" "$expected_points" || return 1
  # smoke: random-sample payload probes (round 2) — the head scroll is
  # deterministic but head-only; T3 proved served corruption can start past
  # it. Random sampling covers the whole id space probabilistically.
  smoke_sample_probes "$target" "$collection" "$expected_points" "$restored_points" || return 1
  # smoke: one vector query — a UNIT vector, not all-zero, sized
  # from the manifest's first configured vector (named or flat). A zero
  # vector is degenerate under Cosine distance (undefined/NaN similarity),
  # so this probe could behave inconsistently across Qdrant versions purely
  # because of the smoke test's OWN choice of input, not anything about the
  # restored data — a unit vector ([1,0,0,...]) is well-defined under
  # Cosine, Euclidean, and Dot alike. Skipped entirely (with an INFO line,
  # never silently) when there is no dense vector config at all — a
  # sparse-only collection has nothing to query here; the scroll smoke above
  # already covers payload sanity for it either way.
  local vectors_empty
  vectors_empty=$(jq -r '(.collection_config.config.params.vectors // {}) | (keys | length) == 0' \
    <<<"$manifest" 2>/dev/null) || vectors_empty="unknown"
  if [ "$vectors_empty" = "true" ]; then
    _printf "restore of %s: no dense vector config (sparse-only collection) — skipping vector smoke test\n" "$collection"
  else
    local vname vsize probe_vec qbody
    vname=$(jq -r '.collection_config.config.params.vectors
                   | if has("size") then "" else (keys | .[0]) end' <<<"$manifest" 2>/dev/null) || {
      _printf "verification failed for %s: cannot read vector config from manifest\n" "$collection" >&2
      return 1
    }
    vsize=$(jq -r '.collection_config.config.params.vectors
                   | if has("size") then .size else .[keys[0]].size end' <<<"$manifest" 2>/dev/null) || {
      _printf "verification failed for %s: cannot read vector size from manifest\n" "$collection" >&2
      return 1
    }
    if ! [[ "$vsize" =~ ^[0-9]+$ ]]; then
      _printf "verification failed for %s: vector size '%s' is not numeric\n" "$collection" "$vsize" >&2
      return 1
    fi
    probe_vec=$(jq -n --argjson n "$vsize" '[range($n) | if . == 0 then 1.0 else 0.0 end]') || {
      _printf "verification failed for %s: cannot build probe vector\n" "$collection" >&2
      return 1
    }
    if [ -n "$vname" ]; then
      qbody=$(jq -n --arg name "$vname" --argjson v "$probe_vec" \
        '{vector: {name: $name, vector: $v}, limit: 1}') || {
        _printf "verification failed for %s: cannot build vector query body\n" "$collection" >&2
        return 1
      }
    else
      qbody=$(jq -n --argjson v "$probe_vec" '{vector: $v, limit: 1}') || {
        _printf "verification failed for %s: cannot build vector query body\n" "$collection" >&2
        return 1
      }
    fi
    resp=$(_curl_rc POST "$target/collections/$collection/points/search" \
      --header "api-key: $QDRANT_API_KEY" --header "Content-Type: application/json" \
      --data "$qbody") || {
      _printf "verification failed for %s: smoke vector query request failed\n" "$collection" >&2
      return 1
    }
    if ! qdrant_status_ok <<<"$resp" >/dev/null; then
      _printf "verification failed for %s: smoke vector query errored\n" "$collection" >&2
      return 1
    fi
  fi
  if [ "$aliases_ok" != "true" ]; then
    _printf "restore of %s from set %s FAILED: alias recreation did not fully succeed (points=%s, manifest=%s, tolerance=%s%%)\n" \
      "$collection" "$set_id" "$restored_points" "$expected_points" "$QDRANT_VERIFY_TOLERANCE_PCT" >&2
    return 1
  fi
  _printf "restore of %s from set %s VERIFIED (points=%s, manifest=%s, tolerance=%s%%)\n" \
    "$collection" "$set_id" "$restored_points" "$expected_points" "$QDRANT_VERIFY_TOLERANCE_PCT"
  return 0
}

recover_snap_shards_task() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      *) _printf "unknown recover_snap_shards option: %s\n" "$1" >&2; usage; exit 1 ;;
    esac
  done
  if ! bool_env_ok "$QDRANT_RESTORE_FORCE"; then
    _printf "recover_snap_shards: QDRANT_RESTORE_FORCE must be 'true' or 'false', got '%s'\n" \
      "$QDRANT_RESTORE_FORCE" >&2
    exit 1
  fi
  if ! bool_env_ok "$QDRANT_SKIP_VERSION_CHECK"; then
    _printf "recover_snap_shards: QDRANT_SKIP_VERSION_CHECK must be 'true' or 'false', got '%s'\n" \
      "$QDRANT_SKIP_VERSION_CHECK" >&2
    exit 1
  fi
  if ! [[ "$QDRANT_VERIFY_TOLERANCE_PCT" =~ ^[0-9]+$ ]] || [ "$QDRANT_VERIFY_TOLERANCE_PCT" -gt 100 ]; then
    _printf "recover_snap_shards: QDRANT_VERIFY_TOLERANCE_PCT must be an integer 0-100, got '%s'\n" \
      "$QDRANT_VERIFY_TOLERANCE_PCT" >&2
    exit 1
  fi
  if ! [[ "$QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]]; then
    _printf "recover_snap_shards: QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS must be a non-negative integer, got '%s'\n" \
      "$QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS" >&2
    exit 1
  fi
  if ! [[ "$QDRANT_VERIFY_POLL_INTERVAL_SECONDS" =~ ^[0-9]+$ ]] || [ "$QDRANT_VERIFY_POLL_INTERVAL_SECONDS" -lt 1 ]; then
    _printf "recover_snap_shards: QDRANT_VERIFY_POLL_INTERVAL_SECONDS must be a positive integer (>= 1), got '%s'\n" \
      "$QDRANT_VERIFY_POLL_INTERVAL_SECONDS" >&2
    exit 1
  fi
  if ! [[ "$QDRANT_VERIFY_SAMPLE_POINTS" =~ ^[0-9]+$ ]]; then
    _printf "recover_snap_shards: QDRANT_VERIFY_SAMPLE_POINTS must be a non-negative integer, got '%s'\n" \
      "$QDRANT_VERIFY_SAMPLE_POINTS" >&2
    exit 1
  fi
  if [ -z "${restore_hosts[0]:-}" ]; then
    _printf "recover_snap_shards: QDRANT_RESTORE_HOSTS must be set\n" >&2
    exit 1
  fi
  warn_ignored_legacy_env "restore"
  setup_s3_storage
  discover_peers "${restore_hosts[0]}" || exit 1
  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
    fetch_collections_from_s3_manifests
  else
    local existing_count; existing_count=$(wc -l < "$QDRANT_COLLECTIONS_FILE" | tr -d ' ')
    _printf "WARNING: reusing existing %s file (%s collection(s)) — delete it or run 'reset' for a fresh fetch\n" \
      "$QDRANT_COLLECTIONS_FILE" "$existing_count"
  fi
  local line collection ok_count=0 fail_count=0 rc=0
  while IFS= read -r line; do
    collection="${line#*,}"
    if [ -z "$collection" ]; then continue; fi
    if restore_one_collection "$collection"; then
      ok_count=$((ok_count + 1))
    else
      fail_count=$((fail_count + 1))
    fi
  done < "$QDRANT_COLLECTIONS_FILE"
  _printf "restore summary: %d collection(s) verified, %d failed\n" "$ok_count" "$fail_count"
  if [ $((ok_count + fail_count)) -eq 0 ]; then
    _printf "WARNING: no collections processed\n"
  fi
  if [ "$fail_count" -gt 0 ]; then rc=1; fi
  exit "$rc"
}

# Discover collections that have manifests (new-format discovery; never mixes
# legacy keys — the legacy/per-shard contamination guard is bidirectional).
fetch_collections_from_s3_manifests() {
  local out names c
  out=$(mc_json_safe ls "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/backup_manifests/") || {
    _printf "fetch_collections_from_s3_manifests: cannot list backup_manifests/ — nothing to restore\n" >&2
    exit 1
  }
  if ! names=$(jq -r 'select(.status == "success" and .type == "folder") | .key | sub("/$"; "")' <<<"$out" 2>&1); then
    _printf "fetch_collections_from_s3_manifests: cannot parse backup_manifests/ listing: %s\n" "$names" >&2
    exit 1
  fi
  while IFS= read -r c; do
    if [ -n "$c" ]; then printf ',%s\n' "$c" >> "$QDRANT_COLLECTIONS_FILE"; fi
  done <<<"$names"
  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
    _printf "fetch_collections_from_s3_manifests: no manifests found in bucket\n" >&2
    exit 1
  fi
}

# Execute only when run as a script; `source` loads functions for tests.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  run "$@"
fi
