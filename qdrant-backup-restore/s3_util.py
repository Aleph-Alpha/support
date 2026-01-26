import os

import boto3
import sys

_session = None

_config = {}

QDRANT_COLLECTIONS_FILE="collections"
QDRANT_SNAPSHOTS_FILE="snapshots"

def get_session():
    aws_access_key_id = _config["aws_access_key_id"]
    aws_secret_access_key = _config["aws_secret_access_key"]
    return boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )

# validates supplied envs configuration
def get_config():
    global _config
    if len(_config) == 0:
        endpoint_url = os.getenv("QDRANT_S3_ENDPOINT_URL")
        aws_access_key_id = os.getenv("QDRANT_S3_ACCESS_KEY_ID")
        aws_secret_access_key = os.getenv("QDRANT_S3_SECRET_ACCESS_KEY")
        bucket_name = os.getenv("QDRANT_S3_BUCKET_NAME")

        if endpoint_url is None:
            print("QDRANT_S3_ENDPOINT_URL is not set")
            sys.exit(1)

        if aws_access_key_id is None:
            print("QDRANT_S3_ACCESS_KEY_ID is not set")
            sys.exit(1)
        if aws_secret_access_key is None:
            print("QDRANT_S3_SECRET_ACCESS_KEY is not set")
            sys.exit(1)

        if bucket_name is None:
            print("QDRANT_S3_BUCKET_NAME is not set")
            sys.exit(1)

        link_expiry_duration = 3600 * 24
        _link_expiry_duration = os.getenv("QDRANT_S3_LINK_EXPIRY_DURATION")
        if _link_expiry_duration is not None:
            link_expiry_duration = _link_expiry_duration

        qdrant_s3_configuration = {
            "endpoint_url": endpoint_url,
            "bucket_name": bucket_name,
            "link_expiry_duration": link_expiry_duration,
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key
        }
        _config = qdrant_s3_configuration
    return None


def list_s3_snapshots(prefix=None):
    endpoint_url = _config["endpoint_url"]

    session = get_session()
    s3 = session.resource(service_name='s3', endpoint_url=endpoint_url)
    bucket_name = _config["bucket_name"]

    bucket = s3.Bucket(bucket_name)

    cm_map = {}
    for obj in bucket.objects.filter(Prefix=prefix):
        path = obj.key
        segments = path.split('/')

        if segments[1] not in cm_map:
            cm_map[segments[1]] = []
        cm_map[segments[1]].append(segments[2])

    with open(QDRANT_COLLECTIONS_FILE, "a") as f:
        for line in list(cm_map.keys()):
             print(f"{endpoint_url},{line}", file=f)

    with open(QDRANT_SNAPSHOTS_FILE, "a") as f:
        for key, lines in cm_map.items():
            for line in lines:
                if "-" in line:
                    part_idx = line.find("-")
                    coll = line[:part_idx]
                else:
                    coll = line
                print(f"{endpoint_url},{coll},{line}", file=f)
    print(cm_map)



# Generates a presigned url that expires in 1 day by default, it can be adjusted accordingly
def generate_short_url(storage_path):
    endpoint_url = _config["endpoint_url"]
    bucket_name = _config["bucket_name"]
    link_expiry_duration = _config["link_expiry_duration"]

    session = get_session()
    s3 = session.client(
        service_name='s3', endpoint_url=endpoint_url
    )

    url = s3.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': bucket_name,
            'Key': storage_path,
        },
        ExpiresIn=link_expiry_duration,
    )
    return url


if __name__ == '__main__':
    get_config()

    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "gen_url":
            storage_path = sys.argv[2]
            print(generate_short_url(storage_path))
        elif command == "list_snapshots":
            list_s3_snapshots("snapshot")
        else:
            print("command not known")
            sys.exit(1)
    else:
        print("S3 storage_path is required!")
        sys.exit(1)
