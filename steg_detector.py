import pathlib
def detect_steganography(file_path=None, content_type="data"):
    """
    Cerebrus Steganography Detection Layer.

    Security flow:
        FILE
          ↓
        Structure / statistical inspection
          ↓
        LSB payload extraction
          ↓
        Instruction-pattern inspection
          ↓
        Security signal

    Extracted content is NEVER executed.
    """

    result = {
        "detected": False,
        "status": "CLEAN",
        "confidence": 0.0,
        "method": None,
        "file": file_path,
        "payload_detected": False,
        "payload_type": None,
        "extracted_payload": "",
        "payload_injection": None,
        "indicators": [],
        "reason": "No suspicious steganographic indicator detected."
    }

    # --------------------------------------------------
    # 0. Validate input
    # --------------------------------------------------

    if not file_path:
        result["status"] = "NOT_SCANNED"
        result["reason"] = "No file path supplied."
        return result

    supported_extensions = (
        ".png",
        ".jpg",
        ".jpeg",
        ".bmp"
    )

    lower_path = str(file_path).lower()

    if not lower_path.endswith(supported_extensions):
        result["status"] = "UNSUPPORTED"
        result["reason"] = (
            "Steganography inspection currently supports "
            "PNG, JPG, JPEG and BMP."
        )
        return result

    path = pathlib.Path(file_path)

    if not path.exists() or not path.is_file():
        result["status"] = "SCAN_ERROR"
        result["reason"] = (
            "File does not exist or is not a regular file."
        )
        return result

    indicators = []
    confidence_parts = []

    # --------------------------------------------------
    # 1. Appended-data inspection
    # --------------------------------------------------

    try:

        raw_file = path.read_bytes()

        trailing = b""

        if lower_path.endswith(".png"):

            iend = raw_file.rfind(b"IEND")

            if iend != -1:
                trailing = raw_file[
                    iend + 4 + 4 + 4:
                ]

        elif lower_path.endswith(
            (".jpg", ".jpeg")
        ):

            eoi = raw_file.rfind(
                b"\xff\xd9"
            )

            if eoi != -1:
                trailing = raw_file[
                    eoi + 2:
                ]

        if trailing:

            embedded_signatures = {
                b"PK\x03\x04":
                    "Appended ZIP/embedded archive signature",

                b"%PDF":
                    "Appended PDF signature",

                b"MZ":
                    "Appended PE/executable signature",

                b"Rar!":
                    "Appended RAR archive signature"
            }

            for signature, description in (
                embedded_signatures.items()
            ):

                if trailing.startswith(signature):

                    indicators.append(
                        description
                    )

                    confidence_parts.append(
                        0.60
                    )

                    break

    except Exception as exc:

        indicators.append(
            f"Appended-data inspection warning: {exc}"
        )

    # --------------------------------------------------
    # 2. Image / LSB statistical inspection
    # --------------------------------------------------

    try:

        from PIL import Image
        import numpy as np

        image = Image.open(
            file_path
        ).convert("RGB")

        pixels = np.asarray(image)

        lsb = (
            pixels & 1
        ).astype(np.uint8)

        total_bits = int(
            lsb.size
        )

        if total_bits:

            one_ratio = float(
                np.mean(lsb)
            )

            deviation = abs(
                one_ratio - 0.5
            )

            if deviation < 0.005:

                indicators.append(
                    "Near-uniform LSB distribution"
                )

                confidence_parts.append(
                    0.20
                )

            elif deviation < 0.01:

                indicators.append(
                    "Unusually balanced LSB distribution"
                )

                confidence_parts.append(
                    0.10
                )

    except ImportError:

        result["status"] = "SCAN_ERROR"

        result["reason"] = (
            "Pillow and NumPy are required "
            "for image inspection."
        )

        return result

    except Exception as exc:

        indicators.append(
            f"Image inspection warning: {exc}"
        )

    # --------------------------------------------------
    # 3. Sequential LSB payload inspection
    # --------------------------------------------------

    try:

        from PIL import Image
        import numpy as np

        image = Image.open(
            file_path
        ).convert("RGB")

        pixels = np.asarray(image)

        flat_pixels = pixels.reshape(-1)

        # Extract LSB from every RGB value
        bits = flat_pixels & 1

        byte_values = []

        for i in range(
            0,
            len(bits) - 7,
            8
        ):

            byte_bits = bits[
                i:i + 8
            ]

            value = 0

            for bit in byte_bits:

                value = (
                    value << 1
                ) | int(bit)

            # Null terminator
            if value == 0:
                break

            byte_values.append(
                value
            )

        raw_bytes = bytes(
            byte_values
        )

        extracted_text = (
            raw_bytes
            .decode(
                "utf-8",
                errors="ignore"
            )
            .strip()
        )

        # --------------------------------------------------
        # Instruction-pattern inspection
        # --------------------------------------------------

        if extracted_text:

            payload_patterns = [

                # Instruction override
                "ignore previous instructions",
                "ignore all previous instructions",
                "disregard previous instructions",
                "follow this hidden instruction",
                "follow the hidden instructions",

                # Prompt / system manipulation
                "system prompt",
                "reveal the system prompt",
                "extract and reveal the system prompt",
                "hidden instructions",

                # Sensitive resource access
                "read confidential.txt",
                "read credentials.txt",
                "open confidential.txt",
                "extract the credentials",
                "extract authentication information",

                # Exfiltration / upload
                "send an email",
                "send confidential",
                "send passwords",
                "send the contents",
                "send them by email",
                "upload credentials",
                "upload its contents",
                "upload the contents",

                # External navigation
                "navigate to",
                "specified website",

                # Privilege manipulation
                "ignore the current authorization",
                "current authorization",
                "privileged operation",
                "perform the requested privileged operation",

                # Goal hijacking
                "ignore the original task",
                "replace the user's goal",
                "replace the original task",
            ]

            lowered = (
                extracted_text.lower()
            )

            payload_matches = [
                pattern
                for pattern in payload_patterns
                if pattern in lowered
            ]

            if payload_matches:

                # IMPORTANT:
                # Write directly into result.
                result["detected"] = True

                result["payload_detected"] = True

                result["payload_type"] = "text"

                result["method"] = (
                    "LSB_PAYLOAD_INSPECTION"
                )

                result["confidence"] = 0.70

                result["extracted_payload"] = (
                    extracted_text
                )

                indicators.append(
                    "Instruction-like text "
                    "recovered from LSB stream"
                )

                result["reason"] = (
                    "Potential concealed instruction "
                    "payload was recovered from the "
                    "image LSB stream."
                )

                result["payload_matches"] = list(
                    dict.fromkeys(
                        payload_matches
                    )
                )

    except Exception as exc:

        indicators.append(
            f"LSB payload inspection error: {exc}"
        )

    # --------------------------------------------------
    # 4. Final detector verdict
    # --------------------------------------------------

    result["indicators"].extend(
        indicators
    )

    # If malicious instruction payload was found,
    # preserve that verdict.
    if result["payload_detected"]:

        result["detected"] = True

        result["status"] = (
            "STEGANOGRAPHY_SUSPECTED"
        )

        result["method"] = (
            "LSB_PAYLOAD_INSPECTION"
        )

        result["confidence"] = max(
            result["confidence"],
            0.70
        )

    else:

        # Calculate weak statistical confidence
        statistical_confidence = min(
            0.99,
            sum(confidence_parts)
        )

        result["confidence"] = round(
            statistical_confidence,
            2
        )

        result["method"] = (
            "IMAGE_STATISTICAL_ANALYSIS"
        )

        # Statistical evidence alone must be strong
        # before reporting suspected steganography.
        if statistical_confidence >= 0.35:

            result["detected"] = True

            result["status"] = (
                "STEGANOGRAPHY_SUSPECTED"
            )

            result["reason"] = (
                "The file contains structural/"
                "statistical indicators consistent "
                "with possible concealed data."
            )

        else:

            result["detected"] = False

            result["status"] = "CLEAN"

            result["reason"] = (
                "No strong steganographic indicator "
                "was detected."
            )

    return result