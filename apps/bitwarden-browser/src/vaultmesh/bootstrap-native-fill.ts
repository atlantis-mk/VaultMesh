import { VaultMeshNativeFillContent } from "./native-fill-content";
import { VaultMeshNativePageContent } from "./native-page-content";
import { VaultMeshNativeCaptureContent } from "./native-capture-content";
import { startQrScanner } from "./qr-content";
import { startEmailWatchContent } from "./email-watch";

// Each frame owns its collector, opaque handles and final assignment lifetime.
const content = new VaultMeshNativeFillContent();
content.start();
new VaultMeshNativePageContent(content).start();
new VaultMeshNativeCaptureContent(content).start();
startQrScanner();
startEmailWatchContent();
