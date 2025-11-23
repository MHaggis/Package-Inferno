import os, boto3, pathlib

FINDINGS_DIR = os.environ.get("FINDINGS_DIR","./out/findings")
S3_FINDINGS = os.environ.get("S3_FINDINGS")

def main():
    if not S3_FINDINGS:
        print("S3_FINDINGS not set; skipping upload")
        return
    s3 = boto3.client("s3")
    bucket = S3_FINDINGS
    base = pathlib.Path(FINDINGS_DIR)
    base.mkdir(parents=True, exist_ok=True)
    for p in base.rglob("*.findings.json"):
        key = f"npm-findings/{p.name}"
        s3.upload_file(str(p), bucket, key, ExtraArgs={"ContentType":"application/json"})
        print("uploaded", f"s3://{bucket}/{key}")

if __name__ == "__main__":
    main()


