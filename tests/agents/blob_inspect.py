"""导出白泽测试中记录的所有 blob 完整数据，供协议合规性检查"""

import argparse
import json
import sys
import time

import requests

from baize_client import BaizeClient


def main():
    parser = argparse.ArgumentParser(description="导出白泽 blob 数据")
    parser.add_argument("--base", default="http://127.0.0.1:9479",
                        help="白泽 API 地址")
    args = parser.parse_args()

    client = BaizeClient(args.base)

    # 等待 server 就绪
    for i in range(30):
        try:
            client.list_agents()
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("错误: 无法连接白泽 server")
        sys.exit(1)

    # 通过 blob query API 获取全部 blob（空 filter = 返回所有）
    resp = client.session.post(
        f"{client.base_url}/api/v0/blobs/query",
        json={"labels": {}},
        headers=client._headers("baize-root"),
    )
    resp.raise_for_status()
    all_blobs = resp.json()
    print(f"总 blob 数: {len(all_blobs)}\n")

    # 按 type label 分组
    by_type = {}
    for blob in all_blobs:
        t = blob.get("labels", {}).get("type", "(无 type)")
        by_type.setdefault(t, []).append(blob)

    for t, blobs in sorted(by_type.items()):
        print(f"{'=' * 60}")
        print(f"type: {t} ({len(blobs)} 个)")
        print(f"{'=' * 60}")
        for i, blob in enumerate(blobs):
            labels = blob.get("labels", {})
            content = blob.get("content", "")
            hash_val = blob.get("hash", "")
            created = blob.get("created_at", "")

            # 尝试解析 JSON content
            try:
                content_obj = json.loads(content)
                content_display = json.dumps(content_obj, ensure_ascii=False, indent=4)
            except (json.JSONDecodeError, TypeError):
                content_display = content[:200] + ("..." if len(content) > 200 else "")

            print(f"\n  [{i+1}] hash={hash_val[:16]}...  created={created}")
            print(f"  labels:")
            for k, v in sorted(labels.items()):
                print(f"    {k}: {v}")
            print(f"  content:")
            for line in content_display.split("\n"):
                print(f"    {line}")
        print()


if __name__ == "__main__":
    main()
