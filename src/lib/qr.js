export async function readOtpUriFromImage(file) {
  if (!("BarcodeDetector" in globalThis)) {
    throw new Error("QR import is not supported in this Chrome build.");
  }

  const bitmap = await createImageBitmap(file);

  try {
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    const results = await detector.detect(bitmap);
    const qrCode = results.find((item) => typeof item.rawValue === "string" && item.rawValue.startsWith("otpauth://"));

    if (!qrCode) {
      throw new Error("No valid OTP QR code was found in the selected image.");
    }

    return qrCode.rawValue;
  } finally {
    bitmap.close();
  }
}
