import { AutofillScriptGenerator } from "../autofill/services/autofill-script-generator";
import { VaultMeshRpcBackground } from "../background/vaultmesh-rpc.background";

// Only the native value-less planner and VaultMesh transport are bootstrapped.
// No upstream account, SDK Vault, cloud sync, analytics or local Vault graph.
const planner = new AutofillScriptGenerator();
new VaultMeshRpcBackground(undefined, () => planner).start();
