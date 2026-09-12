import jsQR from "jsqr";
import { QR_SCAN, QR_CHECK, parseTotpQr, clearQr, type TotpQr } from "./qr-contracts";
import { sendSessionMessage } from "./runtime";
import { z } from "zod";

function visible(element: Element): boolean {
  if (!element.isConnected || !element.getClientRects().length || element.closest('[hidden],[aria-hidden="true"],[inert]')) return false;
  for (let current: Element | null = element; current; current = current.parentElement ?? (current.getRootNode() instanceof ShadowRoot ? (current.getRootNode() as ShadowRoot).host : null)) {
    const style = getComputedStyle(current); if (style.display === "none" || style.visibility !== "visible" || Number(style.opacity) === 0) return false;
  }
  const rect = element.getBoundingClientRect(); return rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth;
}
export async function scanVisibleQr(current: () => boolean, decode = jsQR): Promise<TotpQr[]> {
  const values: TotpQr[] = [];
  const roots: ParentNode[] = [document]; const sources: Element[] = [];
  for (let index = 0; index < roots.length && index < 64; index++) {
    for (const element of Array.from(roots[index].querySelectorAll("*")).slice(0, 3000)) {
      if (element.shadowRoot && roots.length < 64) roots.push(element.shadowRoot);
      if (sources.length < 100 && element.matches('img,canvas,svg,[data-qr-value],a[href^="otpauth://"]') && visible(element)) sources.push(element);
    }
  }
  let decoded = 0;
  const append = (raw: string) => { const value = parseTotpQr(raw); if (value && values.length < 20 && !values.some((entry) => entry.uri === value.uri)) values.push(value); };
  for (const source of sources) {
    if (!current()) { clearQr(values); break; }
    const direct = source.getAttribute("data-qr-value") ?? (source instanceof HTMLAnchorElement ? source.href : source.getAttribute("alt"));
    if (direct && direct.length <= 10000 && direct.startsWith("otpauth:")) append(direct);
    if (!(source instanceof HTMLCanvasElement || source instanceof HTMLImageElement || source instanceof SVGSVGElement) || decoded++ >= 20) continue;
    const canvas = document.createElement("canvas"); let image: HTMLImageElement | undefined; let objectUrl = ""; let pixels: ImageData | undefined;
    try {
      let width: number, height: number;
      if (source instanceof HTMLImageElement) { if (!source.complete) continue; width = source.naturalWidth; height = source.naturalHeight; }
      else if (source instanceof HTMLCanvasElement) { width = source.width; height = source.height; }
      else { width = source.viewBox.baseVal.width || source.getBoundingClientRect().width; height = source.viewBox.baseVal.height || source.getBoundingClientRect().height; }
      if (width < 1 || height < 1) continue;
      const scale = Math.min(1, 1000 / Math.max(width, height)); width = Math.max(1, Math.round(width * scale)); height = Math.max(1, Math.round(height * scale));
      const border = Math.max(4, Math.ceil(Math.min(width, height) * 0.13)); canvas.width = width + border * 2; canvas.height = height + border * 2;
      const context = canvas.getContext("2d", { willReadFrequently: true }); if (!context) continue;
      context.fillStyle = "#fff"; context.fillRect(0, 0, canvas.width, canvas.height);
      if (source instanceof SVGSVGElement) {
        // External SVG resources are not fetched by the decoder.
        if (source.querySelector("image,use,foreignObject,script,style,animate,set") || source.outerHTML.length > 512000
          || [source, ...Array.from(source.querySelectorAll("*"))].some((element) => !["svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon"].includes(element.localName)
            || Array.from(element.attributes).some((attribute) => attribute.name === "style" || /href$/i.test(attribute.name) || /^on/i.test(attribute.name)
              || /url\s*\(/i.test(attribute.value) || attribute.value.includes("\\") || attribute.value.includes("/*")))) continue;
        const copy = source.cloneNode(true) as SVGSVGElement; copy.setAttribute("xmlns", "http://www.w3.org/2000/svg");
        objectUrl = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(copy)], { type: "image/svg+xml" }));
        image = new Image(); image.src = objectUrl;
        let timer: ReturnType<typeof setTimeout>;
        try { await Promise.race([image.decode(), new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("expired")), 1500); })]); }
        finally { clearTimeout(timer!); }
        if (!current() || !visible(source)) continue;
        context.drawImage(image, border, border, width, height);
      } else context.drawImage(source, border, border, width, height);
      pixels = context.getImageData(0, 0, canvas.width, canvas.height);
      const value = decode(pixels.data, canvas.width, canvas.height, { inversionAttempts: "attemptBoth" });
      if (value?.data && current() && visible(source)) append(value.data);
    } catch { /* Tainted, unreadable or unsupported sources fail closed. */ }
    finally { pixels?.data.fill(0); canvas.width = canvas.height = 0; if (image) image.src = ""; if (objectUrl) URL.revokeObjectURL(objectUrl); }
  }
  return values;
}
export function startQrScanner(): void {
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    const parsed = z.object({ kind: z.literal(QR_SCAN), requestId: z.uuid(), url: z.string().url().max(8192), expiresAt: z.number().int().positive() }).strict().safeParse(message);
    if (!parsed.success || sender.id !== chrome.runtime.id || sender.tab || sender.url?.split("#")[0] !== chrome.runtime.getURL("popup/index.html")) return false;
    const request = parsed.data; const deadline = Math.min(request.expiresAt, Date.now() + 10000);
    const current = () => !document.hidden && location.href === request.url && /^https?:$/.test(location.protocol) && Date.now() < deadline;
    void (async () => {
      let values: TotpQr[] = [];
      try {
        if (current() && await sendSessionMessage({ kind: QR_CHECK, requestId: request.requestId, phase: "start" }) === true) {
          values = await scanVisibleQr(current);
          if (!current() || await sendSessionMessage({ kind: QR_CHECK, requestId: request.requestId, phase: "finish" }) !== true) clearQr(values);
        }
        if (!current()) clearQr(values);
        respond({ requestId: request.requestId, values });
      } catch { respond({ requestId: request.requestId, values: [] }); }
      finally { clearQr(values); }
    })(); return true;
  });
}
