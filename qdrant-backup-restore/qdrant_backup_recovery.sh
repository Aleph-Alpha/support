#!/usr/bin/env bash

set -oue pipefail
QDRANT_COLLECTIONS_FILE="collections"
QDRANT_SNAPSHOTS_FILE="snapshots"
QDRANT_FAILED_RECOVERY_FILE="failed_snapshot_recovery"
QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE="snapshot_recovery_history"
QDRANT_ALIAS_RECOVERY_HISTORY_FILE="alias_recovery_history"
QDRANT_PYTHON_UTIL_FILE="s3_util.py"
QDRANT_COLLECTION_ALIASES="collection_aliases"
#QDRANT_INCLUDED_COLLECTIONS="*"
#QDRANT_EXCLUDED_COLLECTIONS=""

_printf() {
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  printf '[%s] ' "$ts"
  printf "$@"
}

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
  
  result=$(curl -X GET -sS  "$host/collections" -H "api-key: $QDRANT_API_KEY")
  status=$(jq -r '.status' <<< "$result")
  if [ "$status" != "ok" ]; then
      _printf "[%s] failed to get collections, got this instead %s\n" "$host" "${result//[[:space:]]/}"
      exit 1
  fi

  track_collection "$host" "$result"

  _printf "completed fetching collections!\n"
}

# Clears and Stores collections from qdrant node in $QDRANT_COLLECTIONS_FILE
track_collection(){
  local host="$1"
  local result="$2"
  jq -c '.result.collections[]' <<< "$result" | while read -r item; do
    local collection_name=""
    collection_name=$(jq -r '.name' <<< "$item")
    printf '%s,%s\n' "$host" "$collection_name" >> $QDRANT_COLLECTIONS_FILE
  done
}

track_created_collection_snapshot() {
    local host="$1"
    local collection_name="$2"
    local result=""
    local status=""
    local snapshot_name=""

    _printf '[%s] creating snapshot %s for %s collection\n' "$host" "$snapshot_name" "$collection_name"

    result=$(curl -sS -X POST "$host/collections/$collection_name/snapshots?wait=true" --header "api-key: $QDRANT_API_KEY")

    status=$(jq -r '.status' <<< "$result")
    snapshot_name=$(jq -r '.result.name' <<< "$result")

    if [ "$status" = "ok" ]; then
      _printf '[%s] Snapshot %s for %s collection created successfully\n' "$host" "$snapshot_name" "$collection_name"
    else
      _printf '[%s] Snapshot %s for %s collection failed with %s\n' "$host" "$snapshot_name" "$collection_name" "${result//[[:space:]]/}"
    fi

    printf '%s,%s,%s\n' "$host" "$collection_name" "$snapshot_name" >> $QDRANT_SNAPSHOTS_FILE
}

create_collection_snapshot() {
  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
      get_collections
  fi

  for host in "${source_hosts[@]}"; do
    while IFS= read -r line; do
      IFS=',' read -ra cols <<< "$line"
      local collection_name="${cols[1]}"
      track_created_collection_snapshot "$host" "$collection_name"
    done < $QDRANT_COLLECTIONS_FILE
  done

  echo "$QDRANT_SNAPSHOTS_FILE file updated!"
}

fetch_collection_snapshot() {
  local host="$1"
  local collection_name="$2"
  local result=""

  _printf "[%s] fetching snapshots for %s collection\n" "$host" "$collection_name"

  result=$(curl -sS -X GET \
          "$host/collections/$collection_name/snapshots" \
          --header "api-key: $QDRANT_API_KEY")
  status=$(jq -r '.status?' <<< "$result")
  if [ "$status" != "ok" ]; then
      _printf "[%s] failed to fetch snapshots for collections %s, got this instead %s\n" "$host" "$collection_name" "${result//[[:space:]]/}"
      return
  fi

  resultLength=$(jq -c '.result | length? // 0' <<< "$result")

  if [ "$resultLength" = 0 ]; then
      _printf "[%s] could not find snapshots for collections %s, got this instead %s\n" "$host" "$collection_name" "${result//[[:space:]]/}"
      return
  fi

  item=$(jq -c '.result[0]' <<< "$result")

  local snapshot_name=""
  snapshot_name=$(jq -r '.name' <<< "$item")
  printf '%s,%s,%s\n' "$host" "$collection_name" "$snapshot_name" >> $QDRANT_SNAPSHOTS_FILE


  _printf "[%s] completed fetching snapshots for %s collection!\n" "$host" "$collection_name"

}

generate_snapshot_file_from_s3() {
  local datetime=""

  if [[ -s "$QDRANT_SNAPSHOTS_FILE" ]]; then
      _printf "snapshots already fetched! ... need a fresh one? clear %s file\n" "$QDRANT_SNAPSHOTS_FILE"
      return
  fi

  result=$(python3 "$QDRANT_PYTHON_UTIL_FILE" list_snapshots)

  echo "$QDRANT_SNAPSHOTS_FILE file updated!"
}

generate_snapshot_file_from_instance() {
  local datetime=""
  if [[ ! -s "$QDRANT_COLLECTIONS_FILE" ]]; then
      get_collections
  fi

  if [[ -s "$QDRANT_SNAPSHOTS_FILE" ]]; then
      _printf "snapshots already fetched! ... need a fresh one? clear %s file\n" "$QDRANT_SNAPSHOTS_FILE"
      return
  fi

  while IFS= read -r line; do
    IFS=',' read -ra cols <<< "$line"
    local host="${cols[0]}"
    local collection_name="${cols[1]}"
    fetch_collection_snapshot "$host" "$collection_name"
  done < $QDRANT_COLLECTIONS_FILE

  echo "$QDRANT_SNAPSHOTS_FILE file updated!"
}

get_s3_url() {
  local collection_name="$1"
  local snapshot_name="$2"
  local url=""
  local key="snapshots/$collection_name/$snapshot_name"
  url=$(python3 "$QDRANT_PYTHON_UTIL_FILE" gen_url "$key")
  s3_presigned_url="$url"
}

recover_collection_snapshot() {
    local host="$1"
    local collection_name="$2"
    local snapshot_name="$3"
    local result=""
    local status=""

    _printf "[%s] started to recover %s snapshot of %s collection...\n" "$host" "$snapshot_name" "$collection_name"

    get_s3_url "$collection_name" "$snapshot_name"


    result=$(curl -sS -X PUT \
               "$host/collections/$collection_name/snapshots/recover?wait=true" \
               --header "api-key: $QDRANT_API_KEY" \
               --header "Content-Type: application/json" \
               --data "{ \"location\": \"$s3_presigned_url\", \"priority\": \"snapshot\" }")

    status=$(jq -r '.status' <<< "$result")

    if [ "$status" != "ok" ]; then
        _printf "[%s] failed to recover %s snapshot of %s collection, got this %s instead\n" "$host" "$snapshot_name" "$collection_name" "${result//[[:space:]]/}"
        printf '%s,%s,%s\n' "$host" "$snapshot_name" "$status" >> $QDRANT_FAILED_RECOVERY_FILE
    else
        _printf "[%s] successfully recovered %s snapshot of %s collection\n" "$host" "$snapshot_name" "$collection_name"
    fi
    printf '%s,%s,%s\n' "$host" "$snapshot_name" "$status" >> $QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE
}

recover_collection_snapshots(){
  if [[ ! -s "$QDRANT_SNAPSHOTS_FILE" ]]; then
      generate_snapshot_file
  fi

  touch "$QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE"

  while IFS= read -r line; do
    IFS=',' read -ra cols <<< "$line"

    for host in "${restore_hosts[@]}"; do
      local collection_name="${cols[1]}"
      local snapshot_name="${cols[2]}"

      history_count=$(grep -cw "$snapshot_name,ok" "$QDRANT_SNAPSHOT_RECOVERY_HISTORY_FILE" || true)

      if [ "$history_count" -gt 0 ]; then

        _printf "[%s] snapshot %s already recovered, skipping!\n" "$host" "$snapshot_name"
        continue
      fi
      recover_collection_snapshot "$host" "$collection_name" "$snapshot_name"
    done
  done < $QDRANT_SNAPSHOTS_FILE
}

get_collection_aliases() {
  local host="${source_hosts[0]}"
  local result=""
  local status=""

  _printf "[%s] fetching collection aliases...\n" "$host"

  result=$(curl -sS -X GET \
             "$host/aliases" \
             --header "api-key: $QDRANT_API_KEY")

  status=$(jq -r '.status' <<< "$result")

  if [ "$status" != "ok" ]; then
      _printf "[%s] failed to fetch collection aliases, got this instead %s\n" "$host" "${result//[[:space:]]/}"
      exit 1
  fi

  jq -c '.result.aliases[]' <<< "$result" | while read -r item; do
    local collection_name=""
    local alias_name=""
    collection_name=$(jq -r '.collection_name' <<< "$item")
    alias_name=$(jq -r '.alias_name' <<< "$item")
    printf '%s,%s\n' "$collection_name" "$alias_name" >> $QDRANT_COLLECTION_ALIASES
  done

  _printf "[%s] completed fetching collection aliases!\n" "$host"

}

recover_collection_alias() {
  local host="${source_hosts[0]}"
  local collection_name="$1"
  local alias_name="$2"
  local status=""
  local result=""

  result=$(curl -sS -X POST \
             "$host/collections/aliases" \
             --header "api-key: $QDRANT_API_KEY" \
             --header "Content-Type: application/json" \
             --data-raw "{
               \"actions\": [
                 {
                   \"create_alias\": {
                     \"collection_name\": \"$collection_name\",
                     \"alias_name\": \"$alias_name}\"
                   }
                 }
               ]
             }")

  status=$(jq -r '.status' <<< "$result")

  if [ "$status" != "ok" ]; then
      _printf "[%s] failed to fetch collection alias %s:%s, got this instead %s\n" "$host" "$collection_name" "$alias_name" "${result//[[:space:]]/}"
      return
  fi

  printf '%s,%s,%s\n' "$collection_name" "$alias_name" "$status" >> $QDRANT_ALIAS_RECOVERY_HISTORY_FILE
}

recover_collection_aliases() {
  if [[ ! -s "$QDRANT_COLLECTION_ALIASES" ]]; then
      get_collection_aliases
  fi

  local host="${restore_hosts[0]}"

  if [ ! -f "$QDRANT_COLLECTION_ALIASES" ]; then
      _printf "[%s] collection aliases do not exist on source!\n" "$host"
      return
  fi

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

  _printf "[%s] completed recovering collection aliases!\n" "$host"
}

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
        mv "$file" "$file.bkp"
      fi
    fi
  done
}

# gets qdrant peer host url using cluster info endpoint. Sets the port to 6333 the http port.
get_peers_from_cluster_info() {
  local host="${source_hosts[0]}"
  result=$(curl -sS "$host/cluster" -H "api-key: $QDRANT_API_KEY")
  source_hosts=()
  items=$(jq -r '.result.peers[].uri' <<< "$result")
  while read -r item; do
    source_hosts+=("${item%??}3")
  done <<< "$items"
}

usage() {
  local command="$1"
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
                        reset - clear the temporary files created on this workspace

Optional arguments:
  --date DATETIME       Datetime of the preferred snapshots, this will fetch the latest time of the given data n time
  -h, --help            Show this help message and exit

Example:
  $0 get_snap
EOF
  elif [ "$command" = "reset" ]; then

    cat <<EOF
Usage: $0 <task> [OPTIONS]

Positional arguments:
  task                  Name of the task (required) i.e;
                        reset - clear the temporary files created on this workspace

Optional arguments:
  --bkp BACKUP       --bkp true if state files should be saved, false by default and when argument not provided.
  -h, --help            Show this help message and exit

Example:
  $0 reset --bkp true
EOF
  fi
}

run() {

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

    if [ "$command" = "get_coll" ]; then
      get_collections
    elif [ "$command" = "get_snap" ]; then
      local DATETIME=""
      while [[ $# -gt 0 ]]; do
          case $1 in
              --time) DATETIME="$2"; shift 2 ;;
              -h|--help) usage "$command"; exit 0 ;;
              *) echo "unknown option: $1"; usage "$command"; exit 1 ;;
          esac
      done
      generate_snapshot_file_from_instance "$DATETIME"
    elif [ "$command" = "get_snap_s3" ]; then
      local DATETIME=""
      while [[ $# -gt 0 ]]; do
          case $1 in
              --time) DATETIME="$2"; shift 2 ;;
              -h|--help) usage "$command"; exit 0 ;;
              *) echo "unknown option: $1"; usage "$command"; exit 1 ;;
          esac
      done
      generate_snapshot_file_from_s3 "$DATETIME"
   elif [ "$command" = "create_snap" ]; then
      create_collection_snapshot
    elif [ "$command" = "recover_snap" ]; then
      recover_collection_snapshots
    elif [ "$command" = "get_colla" ]; then
      get_collection_aliases
    elif [ "$command" = "recover_colla" ]; then
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
}

run "$@"
