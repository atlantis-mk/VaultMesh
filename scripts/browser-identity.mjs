import { createHash } from "node:crypto";

// Repository-pinned public key of the Chrome Web Store item. Development, Review
// sideload and store ZIPs share this identity. It is public identity material, not a
// store signing credential.
export const developmentExtensionKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1VmBabFPaQN47bo15GHTVRUlOgfK1syNFdL2ydmiYYAPtOyWOXwoiAldC56aF3mVoA7LYH3rgxnKLkgGRnH38xBrAmJzYqch+ECBI3pCtyDFgRNtzOGvCpFsKPp4HcfQrWyu4pub6Yx38iAw2kvRJK41BvvtksXoLsgdgfClzGOeavmKPr3XwbSZrNrkhPi7lnliAO8LrE7LGVu49gFEDEu9OXlLv/xrD9R6GoNvY367bIx6QzLpbMi9sPYHBurkLQMuDs6aLj3Oldp1cHK9deqLeDt/rxIariFxo26wf4xkBeRiymO/KcYiLecLyD2C1feSRzhWybzaGl/O90ACmwIDAQAB";

const alphabet = "abcdefghijklmnop";

export function extensionIdFromKey(key) {
  return [...createHash("sha256").update(Buffer.from(key, "base64")).digest().subarray(0, 16)]
    .map((byte) => `${alphabet[byte >> 4]}${alphabet[byte & 0x0f]}`)
    .join("");
}

export const developmentExtensionId = extensionIdFromKey(developmentExtensionKey);
export const firefoxExtensionId = "vaultmesh@atlantis-mk.github.io";
export const sideloadReviewDistribution = "sideload-review";

export function validFirefoxExtensionId(value) {
  return typeof value === "string"
    && value === firefoxExtensionId;
}

export function browserIdentityEnvironment(baseEnvironment = process.env) {
  const extensionKey = baseEnvironment.WXT_CHROME_EXTENSION_KEY ?? developmentExtensionKey;
  const distribution = baseEnvironment.VAULTMESH_EXTENSION_DISTRIBUTION;
  if (distribution && distribution !== sideloadReviewDistribution) {
    throw new Error(`VAULTMESH_EXTENSION_DISTRIBUTION 只支持 ${sideloadReviewDistribution}。`);
  }
  const derivedExtensionId = extensionIdFromKey(extensionKey);
  const extensionId = baseEnvironment.VAULTMESH_BROWSER_EXTENSION_ID ?? derivedExtensionId;
  if (!/^[a-p]{32}$/.test(extensionId)) {
    throw new Error("VAULTMESH_BROWSER_EXTENSION_ID 必须是 32 位 Chrome 扩展 ID。");
  }
  if (extensionId !== derivedExtensionId) {
    throw new Error("VAULTMESH_BROWSER_EXTENSION_ID 与 manifest key 不匹配。");
  }
  const geckoId = baseEnvironment.VAULTMESH_FIREFOX_EXTENSION_ID ?? firefoxExtensionId;
  if (!validFirefoxExtensionId(geckoId)) {
    throw new Error(`VAULTMESH_FIREFOX_EXTENSION_ID 必须固定为 ${firefoxExtensionId}。`);
  }
  return {
    ...baseEnvironment,
    WXT_CHROME_EXTENSION_KEY: extensionKey,
    VAULTMESH_BROWSER_EXTENSION_ID: extensionId,
    VAULTMESH_FIREFOX_EXTENSION_ID: geckoId,
  };
}
