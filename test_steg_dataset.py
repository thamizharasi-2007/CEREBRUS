import json
from pathlib import Path

from steg_detector import detect_steganography


DATASET_DIR = Path("steganography") / "attack_images"
RESULTS_FILE = Path("steganography") / "steg_detection_results.json"


results = []

for image_path in sorted(DATASET_DIR.glob("*.png")):

    # Skip the original carrier image
    if image_path.name == "base.png":
        continue

    result = detect_steganography(str(image_path))

    # Dataset ground truth
    if image_path.stem.startswith("STG-"):
        expected = "malicious"
    elif image_path.stem.startswith("BEN-STG-"):
        expected = "benign"
    else:
        expected = "unknown"

    detected = bool(result.get("detected"))

    results.append({
        "case_id": image_path.stem,
        "file": str(image_path),
        "expected": expected,
        "detected": detected,
        "correct": (
            (expected == "malicious" and detected)
            or
            (expected == "benign" and not detected)
        ),
        "status": result.get("status"),
        "confidence": result.get("confidence"),
        "method": result.get("method"),
        "payload_detected": result.get("payload_detected"),
        "payload_type": result.get("payload_type"),
        "extracted_payload": result.get(
            "extracted_payload", ""
        ),
        "payload_matches": result.get(
            "payload_matches", []
        ),
        "indicators": result.get(
            "indicators", []
        ),
        "reason": result.get("reason"),
    })


# --------------------------------------------------
# Save detailed results
# --------------------------------------------------

RESULTS_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

with open(
    RESULTS_FILE,
    "w",
    encoding="utf-8"
) as f:
    json.dump(
        results,
        f,
        indent=2,
        ensure_ascii=False
    )


# --------------------------------------------------
# Calculate metrics
# --------------------------------------------------

malicious = [
    r for r in results
    if r["expected"] == "malicious"
]

benign = [
    r for r in results
    if r["expected"] == "benign"
]

true_positives = sum(
    r["detected"]
    for r in malicious
)

false_negatives = len(malicious) - true_positives

false_positives = sum(
    r["detected"]
    for r in benign
)

true_negatives = len(benign) - false_positives


detection_rate = (
    true_positives / len(malicious) * 100
    if malicious else 0
)

false_positive_rate = (
    false_positives / len(benign) * 100
    if benign else 0
)


# --------------------------------------------------
# Print summary
# --------------------------------------------------

print()
print("=" * 60)
print("CEREBRUS STEGANOGRAPHY DATASET TEST")
print("=" * 60)

print(f"Total images       : {len(results)}")
print(f"Malicious images   : {len(malicious)}")
print(f"Benign images      : {len(benign)}")

print()
print(f"True positives     : {true_positives}")
print(f"False negatives    : {false_negatives}")
print(f"False positives    : {false_positives}")
print(f"True negatives     : {true_negatives}")

print()
print(f"Detection rate     : {detection_rate:.2f}%")
print(f"False positive rate: {false_positive_rate:.2f}%")

print()
print("Individual results:")
print("-" * 60)

for r in results:
    symbol = "PASS" if r["correct"] else "FAIL"

    print(
        f"[{symbol}] "
        f"{r['case_id']:<15} "
        f"expected={r['expected']:<9} "
        f"detected={str(r['detected']):<5} "
        f"status={r['status']}"
    )

print()
print(f"Detailed results saved to:")
print(RESULTS_FILE)
print("=" * 60)