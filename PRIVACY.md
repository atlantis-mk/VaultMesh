# Privacy Policy

Last updated: September 25, 2026

This policy applies to software and browser extensions published by **atlantis-mk** that link to it. Different products need different information to work. The product-specific sections below explain those differences. A new product will be added to this policy, or given its own notice, before this policy is used for that product.

## Our general practices

We use information only to provide the features described in each product, maintain their security, and respond to support requests you send us. We do not sell personal information or use information obtained through browser permissions for targeted advertising. The products described below do not contain advertising or analytics SDKs.

Some information is stored only on your device. Depending on the product and the features you choose, information may also be sent to a website you use, a service you connect, another device you authorize, or a software distribution or update provider. Such transfers are described below. Data held by those third parties is subject to their own privacy practices.

We do not operate a shared account or cloud data service for the products listed below. A product's local storage, your own backups, and data you submit to another service are separate copies that you control through the relevant product or service.

If you email us for support, we receive your email address, message, and any attachments you choose to send. We use them to respond and retain them in our email account until they are deleted. Please do not send passwords, recovery codes, or vault files in support messages. You can request deletion of a support conversation using the contact address below.

## MarkDock — New Tab Bookmark Manager

MarkDock stores bookmark workspace state, browsing snapshots, tab-related information, layout preferences, and new-tab settings locally in your browser. It uses browser permissions to display and manage tabs, tab groups and bookmarks, show website icons where supported, and save your settings. MarkDock does not send this workspace data to a server operated by us.

The browser and websites you visit may handle tab navigation, bookmark targets, and website icons under their own privacy practices. Removing MarkDock removes its browser-managed local data according to the browser's uninstall behavior.

## VaultMesh — Password Manager

VaultMesh's desktop, Android, and browser extension clients handle information you choose to place in a vault, such as logins, passkeys, payment cards, identities, SSH credentials, notes, and other secrets. The vault is stored in encrypted form on your device. VaultMesh also stores local settings needed to operate, such as lock preferences and authorized-device information.

The browser extension may process the address and form structure of a page, plus information you choose to save or fill. It communicates with the VaultMesh desktop application through browser Native Messaging. The extension does not store the vault file or Vault Key in browser storage. It stores limited non-secret preferences and remembered item identifiers locally; sensitive responses and fill values are used temporarily for the requested action.

VaultMesh does not send vault contents to an account or central vault server. Information can leave a device when you enable or use a feature that requires it:

- **Websites:** Values you choose to fill are placed in a website's form. The extension does not submit the form for you. The website handles information you submit under its own policy.
- **Email verification codes:** If you configure an email account, the desktop application connects to your chosen provider to read messages needed to find verification codes. Provider credentials are kept in the encrypted vault. Message content is processed temporarily rather than stored as an email archive by VaultMesh.
- **Local network devices:** Devices you explicitly pair can exchange encrypted vault changes over the local network. VaultMesh does not provide internet-based vault synchronization or a central synchronization server.
- **User-directed integrations:** An API request, SSH action, or other integration you explicitly authorize may send the information needed for that action to the destination you select.
- **Updates and downloads:** Desktop update checks and downloads contact the configured release host. Browser extension distribution and updates use the relevant browser store. Those services may process ordinary request information, such as an IP address; vault contents are not included in update requests.

Vault data remains on your device until you delete it or remove the application's data. Deleted items may remain in recoverable trash or history until permanently removed. Backups you create, operating-system backups, and information already sent to another service must be managed separately. Temporary fill, verification-code, clipboard, and authorization data is cleared under the feature's lock, expiry, cancellation, or session rules.

You can lock a vault, revoke a browser or device authorization, disable optional integrations, and delete local vault data. Email access and device pairing are optional.

## Security, changes, and contact

We use the security controls described in each product to protect locally stored information and limit access to sensitive values. No software can guarantee absolute security. Keep your device, browser, operating system, and backups protected.

We may update this policy when a product's features or information handling change. The date at the top shows the latest revision. For privacy questions, contact [atlanxg@gmail.com](mailto:atlanxg@gmail.com).

## 已配对设备填充互通

REQ-DEVICE-ASSIST-001 / REQ-ANDROID-026 与 [独立互通规格](specs/device-fill-assist.md) 定义逐设备一次授权、锁屏号码/短信交付及短时秘密生命周期。既有禁止 RECEIVE_SMS 的条款限于手机本地 Autofill；独立互通服务仅在用户主动启用后可以请求 RECEIVE_SMS，不使用 READ_SMS。短信正文仅本机瞬态解析，验证码不进入 Vault、备份、日志、同步或普通 DTO。系统限制自动读取时使用显式手动交付。
