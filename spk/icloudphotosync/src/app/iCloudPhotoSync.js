// ============================================================
// iCloud Photo Sync — DSM 7.2 Native App
// ============================================================

// Ensure namespace exists before helpers hang off it.
Ext.ns("SYNO.SDS.iCloudPhotoSync");

// i18n helper. Resolves a "section:key" via DSM's preloaded texts, falling
// back to the key itself so broken lookups surface visibly. `args` (array)
// is interpolated into {0}, {1}, ... placeholders after lookup.
SYNO.SDS.iCloudPhotoSync._T = function (key, args) {
    var idx = key.indexOf(":");
    var section = idx > 0 ? key.substring(0, idx) : "";
    var subkey = idx > 0 ? key.substring(idx + 1) : key;
    var txt = key;
    try {
        if (typeof _TT === "function") {
            var r = _TT("SYNO.SDS.iCloudPhotoSync.Instance", section, subkey);
            if (r && r !== subkey && r !== key && r !== "") txt = r;
        } else if (typeof _T === "function") {
            var r2 = _T(section, subkey);
            if (r2 && r2 !== subkey && r2 !== key && r2 !== "") txt = r2;
        }
    } catch (e) {}
    if (!args || !args.length) return txt;
    return txt.replace(/\{(\d+)\}/g, function (m, i) {
        return args[+i] !== undefined ? args[+i] : m;
    });
};

// DSM 7-native modal built from SYNO.ux primitives. SYNO.SDS.MessageBox
// is unreliable across DSM versions and falling back to bare Ext.MessageBox
// produces an unstyled dialog, so we always render our own SYNO.ux.Window.
//
// `level`: "info" (default) | "error" | "question"
// `buttons`: array of { text, primary?, choice } -- the choice value is
//   passed back to onClick. Defaults to a single OK button.
SYNO.SDS.iCloudPhotoSync._showDialog = function (opts) {
    var level = opts.level || "info";
    var iconColor = level === "error" ? "#d9534f"
                  : level === "question" ? "#057feb"
                  : "#5bc0de";
    var iconChar  = level === "error" ? "\u26a0"
                  : level === "question" ? "?"
                  : "i";

    var bodyHtml =
        '<table style="width:100%;border-collapse:collapse;">' +
        '<tr><td style="vertical-align:top;width:48px;padding:4px 12px 4px 4px;">' +
        '<div style="width:36px;height:36px;border-radius:50%;background:' + iconColor +
        ';color:#fff;font-size:22px;line-height:36px;text-align:center;font-weight:bold;">' +
        iconChar + '</div>' +
        '</td><td style="vertical-align:top;padding:4px 0 0 0;font-size:13px;line-height:1.45;">' +
        opts.msg + '</td></tr></table>';

    var win;
    var btnDefs = (opts.buttons && opts.buttons.length) ? opts.buttons
                : [{ text: SYNO.SDS.iCloudPhotoSync._T("common:ok"), primary: true, choice: "ok" }];
    var btnItems = btnDefs.map(function (b) {
        return new SYNO.ux.Button({
            text: b.text,
            btnStyle: b.primary ? "blue" : "",
            handler: function () {
                win.close();
                if (opts.onClick) opts.onClick(b.choice);
            }
        });
    });

    var WinCls = (window.SYNO && SYNO.SDS && SYNO.SDS.ModalWindow) ? SYNO.SDS.ModalWindow
               : (window.SYNO && SYNO.ux && SYNO.ux.Window) ? SYNO.ux.Window
               : Ext.Window;
    win = new WinCls({
        title: opts.title || "",
        modal: true,
        width: opts.width || 440,
        height: opts.height || 220,
        resizable: false,
        layout: "fit",
        items: [{
            xtype: "panel",
            border: false,
            bodyStyle: "padding:18px 20px;background:#fff;",
            html: bodyHtml
        }],
        fbar: { items: btnItems }
    });
    win.show();
    return win;
};

// Convenience: simple OK alert. `msg` may contain HTML (e.g. <br>) -- the
// caller is responsible for encoding any user-supplied content.
SYNO.SDS.iCloudPhotoSync._showMsg = function (title, msg, level) {
    SYNO.SDS.iCloudPhotoSync._showDialog({
        title: title,
        msg: String(msg || ""),
        level: level === "error" ? "error" : "info"
    });
};

// Global click bridges for inline onclick attributes in dynamically rendered HTML.
// The OverviewTab repaints via body.update() which strips Ext event listeners,
// so we route clicks through these stable globals instead.
SYNO.SDS.iCloudPhotoSync.triggerReauth = function () {
    var appWin = SYNO.SDS.iCloudPhotoSync._activeAppWin;
    if (!appWin || !appWin.detailPanel) return;
    var data = appWin.detailPanel.overviewTab && appWin.detailPanel.overviewTab.currentAccountData;
    if (!data) return;
    var wizard = new SYNO.SDS.iCloudPhotoSync.AccountWizard({
        owner: appWin,
        appWin: appWin,
        accountList: appWin.accountList,
        reAuthAccountId: data.id,
        reAuthAppleId: data.apple_id
    });
    wizard.show();
};

SYNO.SDS.iCloudPhotoSync.triggerSyncNow = function () {
    var appWin = SYNO.SDS.iCloudPhotoSync._activeAppWin;
    if (!appWin || !appWin.detailPanel || !appWin.detailPanel.overviewTab) return;
    var ot = appWin.detailPanel.overviewTab;
    if (ot._startSync) ot._startSync();
};

// 3-choice dialog (move/redownload/cancel). `onChoice(choice)` receives
// "move", "clear", or "cancel".
SYNO.SDS.iCloudPhotoSync._showTargetMoveDialog = function (title, msg, onChoice) {
    SYNO.SDS.iCloudPhotoSync._showDialog({
        title: title,
        msg: msg,
        level: "question",
        width: 520,
        buttons: [
            { text: SYNO.SDS.iCloudPhotoSync._T("dialog:btn_move"),       primary: true, choice: "move" },
            { text: SYNO.SDS.iCloudPhotoSync._T("dialog:btn_redownload"), choice: "clear" },
            { text: SYNO.SDS.iCloudPhotoSync._T("common:cancel"),         choice: "cancel" }
        ],
        onClick: function (choice) { onChoice(choice); }
    });
};

// --- App Instance ---
Ext.define("SYNO.SDS.iCloudPhotoSync.Instance", {
    extend: "SYNO.SDS.AppInstance",

    appWindowName: "SYNO.SDS.iCloudPhotoSync.MainWindow",

    constructor: function (config) {
        this.callParent([config]);
    },

    onStart: function () {
        if (this.window) {
            this.window.show();
            return;
        }
        this.window = this.openWindow(this.appWindowName, {
            appInstance: this
        });
    },

    onStop: function () {
        if (this.window) {
            this.window.close();
            this.window = null;
        }
    }
});

// --- Main Window (Border Layout) ---
Ext.define("SYNO.SDS.iCloudPhotoSync.MainWindow", {
    extend: "SYNO.SDS.AppWindow",

    constructor: function (config) {
        var self = this;

        // Inject styles for account list
        if (!document.getElementById("ics-styles")) {
            var style = document.createElement("style");
            style.id = "ics-styles";
            style.textContent =
                ".ics-account-item { display: flex; align-items: center; gap: 10px; padding: 10px 14px; margin: 4px 2px 4px 8px; cursor: pointer; border-radius: 8px; border: 1px solid transparent; }" +
                ".ics-account-item:first-child { margin-top: 8px; }" +
                ".ics-account-item:hover { background: #f4f8fc; border-color: #e0e5eb; }" +
                ".x-view-selected .ics-account-item, .ics-account-item.x-view-selected { background: #e3eefa !important; border-color: #c4d8f0 !important; }" +
                ".ics-acct-name { flex: 1; font-weight: 600; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #333; }" +
                // iCloud icon in account list
                ".ics-acct-icon { width: 32px; height: 32px; flex-shrink: 0; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23057feb'%3E%3Cpath d='M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z'/%3E%3C/svg%3E\"); background-size: 28px; background-repeat: no-repeat; background-position: center; }" +
                // Status badges (green dot = ok, red = error, orange = warning)
                ".ics-acct-badge { width: 18px; height: 18px; border-radius: 50%; flex-shrink: 0; }" +
                ".ics-acct-badge-ok { background: #4caf50; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 18 18' fill='white'%3E%3Cpath d='M7 12.17L3.83 9l-1.06 1.06L7 14.24l8.24-8.24-1.06-1.06L7 12.17z'/%3E%3C/svg%3E\"); background-size: 14px; background-repeat: no-repeat; background-position: center; }" +
                ".ics-acct-badge-err { background: #e04040; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 18 18' fill='white'%3E%3Cpath d='M9 3.5a1 1 0 011 1v5a1 1 0 01-2 0v-5a1 1 0 011-1zm0 9a1 1 0 110 2 1 1 0 010-2z'/%3E%3C/svg%3E\"); background-size: 14px; background-repeat: no-repeat; background-position: center; }" +
                ".ics-acct-badge-warn { background: #f0a030; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 18 18' fill='white'%3E%3Cpath d='M9 3.5a1 1 0 011 1v5a1 1 0 01-2 0v-5a1 1 0 011-1zm0 9a1 1 0 110 2 1 1 0 010-2z'/%3E%3C/svg%3E\"); background-size: 14px; background-repeat: no-repeat; background-position: center; }" +
                // Toolbar buttons (Cloud Sync style)
                ".ics-tb-btn { display: flex; align-items: center; justify-content: center; border-radius: 4px; font-size: 18px; font-weight: 600; cursor: pointer; user-select: none; border: 1px solid #ccc; background: #f5f5f5; color: #333; }" +
                ".ics-tb-btn:hover { background: #eaeaea; }" +
                ".ics-tb-btn:active { background: #ddd; }" +
                ".ics-tb-btn-blue { background: #057feb; color: #fff; border-color: #057feb; }" +
                ".ics-tb-btn-blue:hover { background: #046fd0; }" +
                ".ics-tb-btn-blue:active { background: #0360b5; }" +
                ".ics-tb-btn-disabled { opacity: 0.4; cursor: default !important; }" +
                ".ics-tb-btn-disabled:hover { background: #f5f5f5; }" +
                ".ics-album-grid .x-grid3-row { border-bottom: 1px solid #f0f0f0; cursor: pointer; border-left: none; border-right: none; border-top: none; }" +
                ".ics-album-grid .x-grid3 { border: none; }" +
                ".ics-album-grid .x-grid3-body { border: none; }" +
                ".ics-album-grid .x-panel-body { border: none; }" +
                ".ics-album-grid .x-grid3-row-over { background: #f0f5fa; }" +
                ".ics-album-grid .x-grid3-row-selected td { background: #e8f0fe !important; }" +
                ".ics-album-grid .x-grid3-row-selected span { color: #333 !important; }" +
                ".ics-album-grid .x-grid3-cell-inner { padding: 6px 8px; line-height: 22px; }" +
                ".ics-album-grid .x-grid3-col-ics-sync-check { padding: 6px 0 0 0; text-align: center; }" +
                ".ics-album-grid .ics-library-header { cursor: pointer; }" +
                ".ics-album-grid .ics-library-header td { padding: 8px 8px 6px !important; }" +
                ".ics-album-grid .ics-library-header:hover { background: #f5f7fa; }" +
                ".ics-library-arrow { display: inline-block; width: 12px; font-size: 10px; color: #999; transition: transform 0.15s; margin-right: 4px; }" +
                ".ics-library-arrow.collapsed { transform: rotate(-90deg); }" +
                // Native-style checkboxes
                ".syno-ux-checkbox, .syno-ux-checkbox-checked { display: inline-block; border: 1px solid #b0b8c0; border-radius: 3px; background: #fff; cursor: pointer; }" +
                ".syno-ux-checkbox-checked { background: #057feb; border-color: #057feb; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='white'%3E%3Cpath d='M6.5 11.5L3 8l1-1 2.5 2.5L12 4l1 1z'/%3E%3C/svg%3E\"); background-size: 16px; background-repeat: no-repeat; background-position: center; }" +
                ".syno-ux-checkbox-indeterminate { background: #057feb; border-color: #057feb; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='white'%3E%3Crect x='3' y='7' width='10' height='2' rx='1'/%3E%3C/svg%3E\"); background-size: 16px; background-repeat: no-repeat; background-position: center; }" +
                // Settings form layout

                // Section titles in settings
                ".ics-section-title { font-size: 14px; font-weight: 600; color: #333; padding-bottom: 8px; margin-bottom: 8px; border-bottom: 1px solid #e8edf2; }" +
                // DSM-style cards
                ".ics-card { background: #fff; border: 1px solid #e8edf2; border-radius: 8px; padding: 20px; margin-bottom: 16px; }" +
                ".ics-card-title { font-size: 15px; font-weight: bold; color: #333; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid #e8edf2; }" +
                ".ics-info-table { width: 100%; border-collapse: collapse; }" +
                ".ics-info-table td { padding: 7px 0; font-size: 13px; }" +
                ".ics-info-table td:first-child { color: #888; width: 160px; }" +
                ".ics-info-table td:last-child { color: #333; }" +
                // Status badge
                ".ics-status-ok { color: #4caf50; }" +
                ".ics-status-warn { color: #f0a030; }" +
                ".ics-status-err { color: #e04040; }" +
                // Tab bar spacing
                ".ics-detail-tabs > .x-tab-panel-header { padding: 0 12px 0 12px; height: 45px; border-bottom: 1px solid #e0e5eb; }" +
                ".ics-detail-tabs .x-tab-strip-wrap { padding-top: 8px; }" +
                ".ics-detail-tabs .x-tab-strip li { margin-right: 8px; }" +
                ".ics-detail-tabs .x-tab-strip a { padding: 8px 16px; }" +
                // Overview status card (Cloud Sync style)
                ".ics-status-icon { width: 52px; height: 52px; border-radius: 50%; flex-shrink: 0; }" +
                ".ics-icon-ok { background: #4caf50; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z'/%3E%3C/svg%3E\"); background-size: 28px; background-repeat: no-repeat; background-position: center; }" +
                ".ics-icon-syncing { background: #057feb; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z'/%3E%3C/svg%3E\"); background-size: 28px; background-repeat: no-repeat; background-position: center; animation: ics-spin 1.5s linear infinite; }" +
                ".ics-icon-err { background: #e04040; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z'/%3E%3C/svg%3E\"); background-size: 28px; background-repeat: no-repeat; background-position: center; }" +
                ".ics-icon-warn { background: #f0a030; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z'/%3E%3C/svg%3E\"); background-size: 28px; background-repeat: no-repeat; background-position: center; }" +
                ".ics-icon-idle { background: #b0bec5; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z'/%3E%3C/svg%3E\"); background-size: 28px; background-repeat: no-repeat; background-position: center; }" +
                "@keyframes ics-spin { from { transform: rotate(0deg); } to { transform: rotate(-360deg); } }" +
                ".ics-status-title { font-size: 18px; font-weight: 600; color: #333; line-height: 1.3; }" +
                ".ics-status-subtitle { font-size: 13px; color: #666; margin-top: 4px; line-height: 1.4; }" +
                // Overview action buttons
                ".ics-ov-action-btn { display: inline-block; padding: 6px 16px; border-radius: 4px; text-decoration: none; font-size: 13px; cursor: pointer; border: 1px solid #ccc; color: #333; background: #fafafa; }" +
                ".ics-ov-action-btn:hover { background: #f0f0f0; }" +
                ".ics-btn-blue { background: #057feb; color: #fff !important; border-color: #057feb; }" +
                ".ics-btn-blue:hover { background: #046fd0; }" +
                ".ics-btn-red { background: #e04040; color: #fff !important; border-color: #e04040; }" +
                ".ics-btn-red:hover { background: #c93636; }" +
                ".ics-btn-disabled { opacity: 0.5; pointer-events: none; cursor: default; }" +
                // Cart button: render icon to the left of text with proper spacing
                ".ics-cart-btn button { background-image: none !important; padding-left: 24px !important; background-repeat: no-repeat !important; background-position: 4px center !important; background-size: 16px 16px !important; }" +
                ".ics-cart-btn button { background-image: url('/webman/3rdparty/iCloudPhotoSync/images/gallery_16.png') !important; }";
            document.head.appendChild(style);
        }

        SYNO.SDS.iCloudPhotoSync._activeAppWin = this;

        this.accountList = new SYNO.SDS.iCloudPhotoSync.AccountList({
            appWin: this
        });

        this.detailPanel = new SYNO.SDS.iCloudPhotoSync.DetailPanel({
            appWin: this
        });

        this.statusBar = new SYNO.SDS.iCloudPhotoSync.StatusBar({
            appWin: this
        });

        var cfg = Ext.apply({
            title: SYNO.SDS.iCloudPhotoSync._T("app:title"),
            width: 900,
            height: 560,
            minWidth: 750,
            minHeight: 450,
            resizable: true,
            maximizable: true,
            minimizable: true,
            layout: "border",
            items: [
                this.accountList,
                this.detailPanel,
                this.statusBar
            ]
        }, config);

        this.callParent([cfg]);
        this.loadStatus();
        this.accountList.refreshAccounts();
    },

    // Helper: call our Python CGI backend via the 3rdparty path
    apiRequest: function (method, params, callback, usePost) {
        var url = "/webman/3rdparty/iCloudPhotoSync/api.cgi";
        var allParams = Ext.apply({ method: method }, params || {});
        Ext.Ajax.request({
            url: url,
            params: allParams,
            method: usePost ? "POST" : "GET",
            success: function (response) {
                try {
                    var json = Ext.decode(response.responseText);
                    var errMsg = json.error ? json.error.message : "";
                    if (callback) callback(json.success, json.data || {}, errMsg, json.error || null);
                } catch (e) {
                    if (callback) callback(false, {}, SYNO.SDS.iCloudPhotoSync._T("common:invalid_response"));
                }
            },
            failure: function () {
                if (callback) callback(false, {}, SYNO.SDS.iCloudPhotoSync._T("common:connection_failed"));
            }
        });
    },

    loadStatus: function () {
        var self = this;
        this.apiRequest("status", { action: "get" }, function (success, data) {
            if (success && data) {
                self.statusBar.updateStatus(data);
            }
        });
    }
});

// --- Account List (West Panel) ---
Ext.define("SYNO.SDS.iCloudPhotoSync.AccountList", {
    extend: "Ext.Panel",

    constructor: function (config) {
        var self = this;

        this.accountStore = new Ext.data.JsonStore({
            fields: ["id", "apple_id", "status", "photo_count"],
            data: []
        });

        this.dataView = new Ext.DataView({
            store: this.accountStore,
            tpl: new Ext.XTemplate(
                '<tpl for=".">',
                '<div class="ics-account-item x-view-item">',
                '<div class="ics-acct-icon"></div>',
                '<div class="ics-acct-name">{apple_id}</div>',
                '<tpl if="status == \'authenticated\'"><div class="ics-acct-badge ics-acct-badge-ok"></div></tpl>',
                '<tpl if="status == \'re_auth_needed\'"><div class="ics-acct-badge ics-acct-badge-err"></div></tpl>',
                '<tpl if="status == \'pending_2fa\'"><div class="ics-acct-badge ics-acct-badge-warn"></div></tpl>',
                '</div>',
                '</tpl>'
            ),
            itemSelector: "div.ics-account-item",
            singleSelect: true,
            autoScroll: true,
            emptyText: '<div style="padding: 20px; text-align: center; color: #999;">' + SYNO.SDS.iCloudPhotoSync._T("account:empty_list") + '</div>',
            listeners: {
                click: function (view, idx) {
                    var record = self.accountStore.getAt(idx);
                    if (record) {
                        self.selectedAccount = record;
                        self.appWin.detailPanel.loadAccount(record.data);
                        self.enableRemoveBtn(true);
                    }
                }
            }
        });

        this.selectedAccount = null;

        // Cloud Sync style toolbar: wide blue "+" and smaller settings-style "−"
        this.addBtn = new SYNO.ux.Button({
            itemId: "createConnection",
            text: "+",
            flex: 2,
            height: 28,
            cls: "syno-ux-button-blue",
            handler: function () { self.onAddAccount(); }
        });

        this.removeBtn = new SYNO.ux.Button({
            itemId: "removeConnection",
            text: "\u2212",
            flex: 1,
            height: 28,
            disabled: true,
            handler: function () { self.onRemoveAccount(); }
        });

        this.toolbarPanel = new Ext.Panel({
            region: "north",
            height: 46,
            border: false,
            layout: {type: "hbox"},
            bodyStyle: "padding: 8px 8px; background: #fff; border-bottom: 1px solid #e0e5eb;",
            items: [this.addBtn, {xtype: "spacer", width: 6}, this.removeBtn]
        });

        var cfg = Ext.apply({
            region: "west",
            width: 250,
            split: true,
            collapsible: false,
            layout: "border",
            border: false,
            cls: "ics-west-panel",
            items: [
                this.toolbarPanel,
            {
                region: "center",
                layout: "fit",
                border: false,
                items: [this.dataView]
            }]
        }, config);

        delete cfg.appWin;
        this.appWin = config.appWin;
        this.callParent([cfg]);

    },

    enableRemoveBtn: function (enabled) {
        this.removeBtn.setDisabled(!enabled);
    },

    onAddAccount: function () {
        var wizard = new SYNO.SDS.iCloudPhotoSync.AccountWizard({
            appWin: this.appWin,
            accountList: this
        });
        wizard.show();
    },

    onRemoveAccount: function () {
        var self = this;
        if (!this.selectedAccount) return;

        var appleId = this.selectedAccount.get("apple_id");
        var accountId = this.selectedAccount.get("id");

        this.appWin.getMsgBox().confirmDelete(
            SYNO.SDS.iCloudPhotoSync._T("account:remove_title"),
            SYNO.SDS.iCloudPhotoSync._T("account:remove_confirm", [Ext.util.Format.htmlEncode(appleId)]),
            function (btn) {
                if (btn === "yes") {
                    self.appWin.apiRequest("account", {
                        action: "remove",
                        account_id: accountId
                    }, function (success) {
                        self.selectedAccount = null;
                        self.enableRemoveBtn(false);
                        if (self.appWin && self.appWin.detailPanel) {
                            self.appWin.detailPanel.clearAccount();
                        }
                        self.refreshAccounts();
                        self.appWin.loadStatus();
                    });
                }
            }
        );
    },

    refreshAccounts: function () {
        var self = this;
        this.appWin.apiRequest("account", { action: "list" }, function (success, data) {
            if (success && data && data.accounts) {
                self.accountStore.loadData(data.accounts);
                if (self.dataView && self.dataView.refresh) {
                    self.dataView.refresh();
                }
                // Auto-select first account if none selected
                if (!self.selectedAccount && data.accounts.length > 0) {
                    var first = self.accountStore.getAt(0);
                    self.selectedAccount = first;
                    self.dataView.select(0);
                    self.appWin.detailPanel.loadAccount(first.data);
                    self.enableRemoveBtn(true);
                }
            }
        });
    }
});

// --- Detail Panel (Center, TabPanel) ---
Ext.define("SYNO.SDS.iCloudPhotoSync.DetailPanel", {
    extend: "SYNO.ux.TabPanel",

    constructor: function (config) {
        this.overviewTab = new SYNO.SDS.iCloudPhotoSync.OverviewTab({
            appWin: config.appWin
        });

        this.albumTab = new SYNO.SDS.iCloudPhotoSync.AlbumGrid({
            appWin: config.appWin
        });

        this.settingsTab = new SYNO.SDS.iCloudPhotoSync.SyncSettings({
            appWin: config.appWin
        });

        this.logTab = new SYNO.SDS.iCloudPhotoSync.LogViewer({
            appWin: config.appWin
        });

        this.aboutTab = new SYNO.SDS.iCloudPhotoSync.AboutTab({
            appWin: config.appWin
        });

        var self = this;

        var cfg = Ext.apply({
            region: "center",
            activeTab: 0,
            plain: true,
            cls: "ics-detail-tabs",
            items: [
                this.overviewTab,
                this.albumTab,
                this.settingsTab,
                this.logTab,
                this.aboutTab
            ],
            listeners: {
                tabchange: function (panel, tab) {
                    if (tab === self.albumTab && self.currentAccount &&
                        self.currentAccount.status === "authenticated" &&
                        !self.albumTab.currentAccountId) {
                        self.albumTab.loadAlbums(self.currentAccount.id);
                    }
                }
            }
        }, config);

        delete cfg.appWin;
        this.appWin = config.appWin;
        this.callParent([cfg]);
    },

    clearAccount: function () {
        this.currentAccount = null;
        if (this.overviewTab.clearAccount) this.overviewTab.clearAccount();
        if (this.albumTab) this.albumTab.currentAccountId = null;
    },

    loadAccount: function (accountData) {
        if (!accountData) {
            this.clearAccount();
            return;
        }
        this.currentAccount = accountData;
        this.overviewTab.loadAccount(accountData);
        this.settingsTab.loadConfig(accountData.id);
        if (accountData.status === "authenticated") {
            // Load albums if album tab is currently active
            if (this.getActiveTab() === this.albumTab) {
                this.albumTab.loadAlbums(accountData.id);
            } else {
                // Reset so tabchange listener triggers load
                this.albumTab.currentAccountId = null;
            }
        }
    }
});

// --- Overview Tab ---
Ext.define("SYNO.SDS.iCloudPhotoSync.OverviewTab", {
    extend: "Ext.Panel",

    constructor: function (config) {
        var cfg = Ext.apply({
            title: SYNO.SDS.iCloudPhotoSync._T("tab:overview"),
            layout: "fit",
            border: false,
            autoScroll: true,
            bodyStyle: "background: #f5f8fb;",
            html: '<div style="text-align: center; padding: 60px 20px; color: #999;">' +
                  '<div style="font-size: 48px; margin-bottom: 16px;">\u2601</div>' +
                  '<h2 style="color: #555; margin-bottom: 8px;">' + SYNO.SDS.iCloudPhotoSync._T("app:title") + '</h2>' +
                  '<p>' + SYNO.SDS.iCloudPhotoSync._T("overview:empty_subtitle") + '</p>' +
                  '</div>'
        }, config);

        delete cfg.appWin;
        this.appWin = config.appWin;
        this.callParent([cfg]);
    },

    clearAccount: function () {
        this.currentAccountData = null;
        var emptyHtml = '<div style="text-align: center; padding: 60px 20px; color: #999;">' +
                  '<div style="font-size: 48px; margin-bottom: 16px;">\u2601</div>' +
                  '<h2 style="color: #555; margin-bottom: 8px;">' + SYNO.SDS.iCloudPhotoSync._T("app:title") + '</h2>' +
                  '<p>' + SYNO.SDS.iCloudPhotoSync._T("overview:empty_subtitle") + '</p>' +
                  '</div>';
        if (this.body) this.body.update(emptyHtml);
    },

    _statusHtml: function (iconCls, title, subtitle, btnId, btnLabel, btnCls) {
        // Cloud Sync style: status card with large icon, title, subtitle, and action button
        var btnHtml = "";
        if (btnId && btnLabel) {
            var inline = "";
            if (btnId === "ics-reauth-btn") {
                inline = ' onclick="SYNO.SDS.iCloudPhotoSync.triggerReauth();return false;"';
            } else if (btnId === "ics-sync-now-btn") {
                inline = ' onclick="SYNO.SDS.iCloudPhotoSync.triggerSyncNow();return false;"';
            }
            btnHtml = '<div class="ics-ov-btn-row" style="margin-top: 12px;">' +
                '<a href="#" id="' + btnId + '" class="ics-ov-action-btn ' + (btnCls || "") + '"' + inline + '>' + btnLabel + '</a>' +
                '</div>';
        }
        return '<div class="ics-card" style="padding: 28px 32px;">' +
            '<div style="display: flex; align-items: center; gap: 20px;">' +
            '<div class="ics-status-icon ' + iconCls + '"></div>' +
            '<div style="flex: 1;">' +
            '<div class="ics-status-title">' + title + '</div>' +
            '<div class="ics-status-subtitle" id="ics-ov-subtitle">' + subtitle + '</div>' +
            btnHtml +
            '</div>' +
            '</div>' +
            '</div>';
    },

    _formatSize: function (size) {
        if (!size || size <= 0) return "—";
        if (size < 1024 * 1024) return Math.round(size / 1024) + " KB";
        if (size < 1024 * 1024 * 1024) return (size / (1024 * 1024)).toFixed(1) + " MB";
        return (size / (1024 * 1024 * 1024)).toFixed(2) + " GB";
    },

    _formatDate: function (ts) {
        if (!ts || ts <= 0) return "—";
        var d = new Date(ts * 1000);
        return d.toLocaleDateString("de-DE") + " " + d.toLocaleTimeString("de-DE", {hour: "2-digit", minute: "2-digit"});
    },

    loadAccount: function (accountData) {
        var self = this;
        if (this._syncPollTimer) {
            clearTimeout(this._syncPollTimer);
            this._syncPollTimer = null;
        }
        this.currentAccountData = accountData;

        var statusCard, statusClass;
        if (accountData.status === "authenticated") {
            statusCard = this._statusHtml(
                "ics-icon-ok",
                SYNO.SDS.iCloudPhotoSync._T("overview:status_uptodate"),
                SYNO.SDS.iCloudPhotoSync._T("overview:status_connected"),
                "ics-sync-now-btn", SYNO.SDS.iCloudPhotoSync._T("overview:btn_sync_now"), "ics-btn-blue"
            );
            statusClass = "ics-status-ok";
        } else if (accountData.status === "pending_2fa") {
            statusCard = this._statusHtml(
                "ics-icon-warn",
                SYNO.SDS.iCloudPhotoSync._T("overview:status_pending_2fa"),
                SYNO.SDS.iCloudPhotoSync._T("overview:status_2fa_pending_msg"),
                "ics-reauth-btn", SYNO.SDS.iCloudPhotoSync._T("overview:btn_reauth"), "ics-btn-blue"
            );
            statusClass = "ics-status-warn";
        } else if (accountData.status === "re_auth_needed") {
            statusCard = this._statusHtml(
                "ics-icon-err",
                SYNO.SDS.iCloudPhotoSync._T("overview:status_reauth_needed"),
                SYNO.SDS.iCloudPhotoSync._T("overview:status_session_expired"),
                "ics-reauth-btn", SYNO.SDS.iCloudPhotoSync._T("overview:btn_reauth"), "ics-btn-red"
            );
            statusClass = "ics-status-err";
        } else {
            statusCard = this._statusHtml(
                "ics-icon-idle",
                SYNO.SDS.iCloudPhotoSync._T("app:title"),
                accountData.status || "--",
                null, null
            );
            statusClass = "";
        }

        var cs = this._cachedStats || {};
        var html = '<div style="padding: 20px;">' +
            statusCard +
            // Connection info card
            '<div class="ics-card">' +
            '<div class="ics-card-title">' + SYNO.SDS.iCloudPhotoSync._T("overview:card_connection_info") + '</div>' +
            '<table class="ics-info-table">' +
            '<tr><td>' + SYNO.SDS.iCloudPhotoSync._T("overview:label_cloud_type") + '</td><td>' + SYNO.SDS.iCloudPhotoSync._T("overview:value_apple_icloud") + '</td></tr>' +
            '<tr><td>' + SYNO.SDS.iCloudPhotoSync._T("overview:label_apple_id") + '</td><td>' + Ext.util.Format.htmlEncode(accountData.apple_id) + '</td></tr>' +
            '<tr><td>' + SYNO.SDS.iCloudPhotoSync._T("overview:label_status") + '</td><td><span class="' + statusClass + '">' +
            (accountData.status === "authenticated" ? SYNO.SDS.iCloudPhotoSync._T("overview:status_signed_in") :
             accountData.status === "re_auth_needed" ? SYNO.SDS.iCloudPhotoSync._T("overview:status_reauth_needed") :
             accountData.status === "pending_2fa" ? SYNO.SDS.iCloudPhotoSync._T("overview:status_wait_2fa") : (accountData.status || "--")) +
            '</span></td></tr>' +
            '<tr><td>' + SYNO.SDS.iCloudPhotoSync._T("overview:label_synced") + '</td><td id="ics-ov-synced">' + (cs.syncedText || '\u2014') + '</td></tr>' +
            '<tr><td>' + SYNO.SDS.iCloudPhotoSync._T("overview:label_storage") + '</td><td id="ics-ov-size">' + (cs.sizeText || '\u2014') + '</td></tr>' +
            '<tr><td>' + SYNO.SDS.iCloudPhotoSync._T("overview:label_last_sync") + '</td><td id="ics-ov-lastsync">' + (cs.lastSyncText || '\u2014') + '</td></tr>' +
            '<tr><td>' + SYNO.SDS.iCloudPhotoSync._T("overview:label_last_run") + '</td><td id="ics-ov-lastrun">' + (cs.lastRunText || '\u2014') + '</td></tr>' +
            '<tr id="ics-ov-warnings-row" style="display:none;"><td>' + SYNO.SDS.iCloudPhotoSync._T("overview:label_warnings") + '</td><td id="ics-ov-warnings" style="color:#b8860b;"></td></tr>' +
            '</table>' +
            '</div>' +
            '</div>';

        this.body.update(html);

        // Attach native click handlers directly on the rendered links.
        // body.update() replaces innerHTML so we re-attach every render.
        setTimeout(function () {
            var bodyEl = self.body && self.body.dom;
            if (!bodyEl) return;
            var syncEl = bodyEl.querySelector("#ics-sync-now-btn");
            if (syncEl) {
                syncEl.onclick = function (ev) {
                    ev.preventDefault();
                    self._startSync();
                    return false;
                };
            }
            var reauthEl = bodyEl.querySelector("#ics-reauth-btn");
            if (reauthEl) {
                reauthEl.onclick = function (ev) {
                    ev.preventDefault();
                    var data = self.currentAccountData;
                    if (!data) return false;
                    var wizard = new SYNO.SDS.iCloudPhotoSync.AccountWizard({
                        owner: self.appWin,
                        appWin: self.appWin,
                        accountList: self.appWin.accountList,
                        reAuthAccountId: data.id,
                        reAuthAppleId: data.apple_id
                    });
                    wizard.show();
                    return false;
                };
            }
        }, 0);

        // Load sync stats from manifest
        if (accountData.status === "authenticated") {
            this.appWin.apiRequest("sync", {
                action: "status",
                account_id: accountData.id
            }, function (success, data) {
                if (!success || !data) return;
                var syncing0 = (data.status === "syncing" || data.status === "starting");
                // Push initial syncing state to settings + albums so their
                // banners reflect reality immediately, before the poll loop
                // takes over.
                if (self.appWin && self.appWin.detailPanel) {
                    var dp0 = self.appWin.detailPanel;
                    if (dp0.settingsTab && dp0.settingsTab.setSyncRunning) {
                        dp0.settingsTab.setSyncRunning(syncing0);
                    }
                    if (dp0.albumTab && dp0.albumTab.setSyncRunning) {
                        dp0.albumTab.setSyncRunning(syncing0);
                    }
                }
                // If a sync is already running (started by the scheduler or a
                // previous UI session), switch into the syncing view and poll.
                if (syncing0) {
                    self._pollSyncStatus(accountData.id);
                }
                // Also check if a move is active.
                self._pollMoveStatus(accountData.id, true);
                self._updateStatsFromData(data);
            });
        }
    },

    _setSyncingState: function (title, subtitle) {
        var self = this;
        // Update the status card in-place to show syncing state
        var iconEl = this.body.dom.querySelector(".ics-status-icon");
        var titleEl = this.body.dom.querySelector(".ics-status-title");
        var subtitleEl = Ext.get("ics-ov-subtitle");
        var syncBtn = Ext.get("ics-sync-now-btn");
        var stopBtn = Ext.get("ics-stop-sync-btn");

        if (iconEl) iconEl.className = "ics-status-icon ics-icon-syncing";
        if (titleEl) titleEl.innerHTML = title;
        if (subtitleEl) subtitleEl.update(subtitle);

        // Ensure the progress bar element exists just above the button row.
        var progEl = Ext.get("ics-sync-progress");
        if (!progEl) {
            var btnRow = this.body.dom.querySelector(".ics-ov-btn-row");
            if (btnRow && btnRow.parentNode) {
                var wrap = document.createElement("div");
                wrap.id = "ics-sync-progress";
                wrap.style.cssText = "margin:8px 0;display:none;";
                wrap.innerHTML =
                    '<div style="background:#e5e7eb;border-radius:4px;height:8px;overflow:hidden;">' +
                      '<div class="ics-sync-progress-fill" style="background:#2a84ff;height:100%;width:0%;transition:width .3s;"></div>' +
                    '</div>' +
                    '<div class="ics-sync-progress-text" style="font-size:12px;color:#888;margin-top:4px;"></div>';
                btnRow.parentNode.insertBefore(wrap, btnRow);
            }
        }

        // Hide sync button, show stop button
        if (syncBtn) syncBtn.dom.style.display = "none";
        if (!stopBtn) {
            // Create stop button next to sync button
            var container = this.body.dom.querySelector(".ics-ov-btn-row");
            if (container) {
                var stopHtml = '<a href="#" id="ics-stop-sync-btn" class="ics-ov-action-btn ics-btn-red">' + SYNO.SDS.iCloudPhotoSync._T("overview:btn_stop_sync") + '</a>';
                var tmpEl = document.createElement("span");
                tmpEl.innerHTML = stopHtml;
                container.appendChild(tmpEl.firstChild);
                stopBtn = Ext.get("ics-stop-sync-btn");
            }
        }
        if (stopBtn) {
            stopBtn.dom.style.display = "";
            // Preserve the "Wird abgebrochen..." state if a stop was already
            // requested — the 3s poll would otherwise reset button text/class
            // back to "Abbrechen" while the runner is still winding down.
            if (this._stopRequested) {
                stopBtn.dom.innerHTML = SYNO.SDS.iCloudPhotoSync._T("overview:status_stopping");
                stopBtn.dom.className = "ics-ov-action-btn ics-btn-disabled";
            } else {
                stopBtn.removeAllListeners();
                stopBtn.on("click", function (e) {
                    e.preventDefault();
                    self._stopSync();
                });
            }
        }
    },

    _setErrorState: function (title, subtitle) {
        var iconEl = this.body.dom.querySelector(".ics-status-icon");
        var titleEl = this.body.dom.querySelector(".ics-status-title");
        var subtitleEl = Ext.get("ics-ov-subtitle");
        var syncBtn = Ext.get("ics-sync-now-btn");
        var stopBtn = Ext.get("ics-stop-sync-btn");

        if (iconEl) iconEl.className = "ics-status-icon ics-icon-err";
        if (titleEl) titleEl.innerHTML = title;
        if (subtitleEl) subtitleEl.update(subtitle);

        // Show sync button again, hide stop button
        if (syncBtn) syncBtn.dom.style.display = "";
        if (stopBtn) stopBtn.dom.style.display = "none";
    },

    _setIdleState: function (title, subtitle) {
        var iconEl = this.body.dom.querySelector(".ics-status-icon");
        var titleEl = this.body.dom.querySelector(".ics-status-title");
        var subtitleEl = Ext.get("ics-ov-subtitle");
        var syncBtn = Ext.get("ics-sync-now-btn");
        var stopBtn = Ext.get("ics-stop-sync-btn");
        var progWrap = Ext.get("ics-sync-progress");

        if (iconEl) iconEl.className = "ics-status-icon ics-icon-ok";
        if (titleEl) titleEl.innerHTML = title;
        if (subtitleEl) subtitleEl.update(subtitle);

        if (syncBtn) syncBtn.dom.style.display = "";
        if (stopBtn) stopBtn.dom.style.display = "none";
        if (progWrap) progWrap.dom.style.display = "none";
    },

    _setWarningState: function (title, warnings) {
        var self = this;
        var iconEl = this.body.dom.querySelector(".ics-status-icon");
        var titleEl = this.body.dom.querySelector(".ics-status-title");
        var subtitleEl = Ext.get("ics-ov-subtitle");
        var syncBtn = Ext.get("ics-sync-now-btn");
        var stopBtn = Ext.get("ics-stop-sync-btn");
        var progWrap = Ext.get("ics-sync-progress");

        if (iconEl) iconEl.className = "ics-status-icon ics-icon-warn";
        if (titleEl) titleEl.innerHTML = title;
        if (subtitleEl) {
            var warnHtml = '<span style="color:#b8860b;">' +
                Ext.util.Format.htmlEncode(warnings.join("; ")) +
                '</span> — <a href="#" id="ics-warn-log-link" style="color:#057feb;text-decoration:underline;">' +
                SYNO.SDS.iCloudPhotoSync._T("overview:link_show_log") + '</a>';
            subtitleEl.update(warnHtml);
            var logLink = document.getElementById("ics-warn-log-link");
            if (logLink) {
                logLink.onclick = function (e) {
                    e.preventDefault();
                    var tabs = self.ownerCt;
                    if (tabs && tabs.setActiveTab) {
                        tabs.items.each(function (item) {
                            if (item instanceof SYNO.SDS.iCloudPhotoSync.LogViewer) {
                                tabs.setActiveTab(item);
                                return false;
                            }
                        });
                    }
                };
            }
        }

        if (syncBtn) syncBtn.dom.style.display = "";
        if (stopBtn) stopBtn.dom.style.display = "none";
        if (progWrap) progWrap.dom.style.display = "none";
    },

    _updateStatsFromData: function (data) {
        if (!data || !data.manifest) return;
        var self = this;
        var m = data.manifest;
        var syncedText = m.total_synced > 0 ? SYNO.SDS.iCloudPhotoSync._T("overview:items_synced", [m.total_synced.toLocaleString("de-DE")]) : SYNO.SDS.iCloudPhotoSync._T("overview:not_yet_synced");
        var sizeText = this._formatSize(m.total_size);
        var lastSyncText = this._formatDate(m.last_sync);
        var lastRunText = this._formatDate(data.finished_at);

        this._cachedStats = {
            syncedText: syncedText,
            sizeText: sizeText,
            lastSyncText: lastSyncText,
            lastRunText: lastRunText
        };

        var el;
        el = Ext.get("ics-ov-synced");
        if (el) el.update(syncedText);
        el = Ext.get("ics-ov-size");
        if (el) el.update(sizeText);
        el = Ext.get("ics-ov-lastsync");
        if (el) el.update(lastSyncText);
        el = Ext.get("ics-ov-lastrun");
        if (el) el.update(lastRunText);

        var warnRow = document.getElementById("ics-ov-warnings-row");
        var warnEl = Ext.get("ics-ov-warnings");
        var hasWarnings = (data.warnings && data.warnings.length > 0) || (data.failed_photos > 0);
        if (warnRow && warnEl) {
            if (hasWarnings) {
                var warnList = (data.warnings || []).slice();
                if (data.failed_photos > 0 && warnList.length === 0) {
                    warnList.push(data.failed_photos + " file(s) failed");
                }
                warnRow.style.display = "";
                warnEl.update(Ext.util.Format.htmlEncode(warnList.join("; ")) +
                    ' — <a href="#" id="ics-warn-log-link2" style="color:#057feb;text-decoration:underline;">' +
                    SYNO.SDS.iCloudPhotoSync._T("overview:link_show_log") + '</a>');
                var logLink2 = document.getElementById("ics-warn-log-link2");
                if (logLink2) {
                    logLink2.onclick = function (e) {
                        e.preventDefault();
                        var tabs = self.ownerCt;
                        if (tabs && tabs.setActiveTab) {
                            tabs.items.each(function (item) {
                                if (item instanceof SYNO.SDS.iCloudPhotoSync.LogViewer) {
                                    tabs.setActiveTab(item);
                                    return false;
                                }
                            });
                        }
                    };
                }
            } else {
                warnRow.style.display = "none";
            }
        }
    },

    _refreshStats: function (accountId) {
        var self = this;
        this.appWin.apiRequest("sync", {
            action: "status",
            account_id: accountId
        }, function (success, data) {
            if (!success || !data) return;
            self._updateStatsFromData(data);
        });
    },

    _startSync: function () {
        var self = this;
        if (!this.currentAccountData) return;
        var accountId = this.currentAccountData.id;

        this._setSyncingState(SYNO.SDS.iCloudPhotoSync._T("overview:status_syncing"), SYNO.SDS.iCloudPhotoSync._T("overview:status_starting"));

        this.appWin.apiRequest("sync", {
            action: "start",
            account_id: accountId
        }, function (success, data, errMsg) {
            if (!success) {
                self._setErrorState(SYNO.SDS.iCloudPhotoSync._T("overview:status_error"), Ext.util.Format.htmlEncode(errMsg));
                return;
            }
            self._pollSyncStatus(accountId);
        });
    },

    _stopSync: function () {
        var self = this;
        if (!this.currentAccountData) return;
        var accountId = this.currentAccountData.id;

        this._stopRequested = true;
        var stopBtn = Ext.get("ics-stop-sync-btn");
        if (stopBtn) {
            stopBtn.dom.innerHTML = SYNO.SDS.iCloudPhotoSync._T("overview:status_stopping");
            stopBtn.dom.className = "ics-ov-action-btn ics-btn-disabled";
            stopBtn.removeAllListeners();
        }

        this.appWin.apiRequest("sync", {
            action: "stop",
            account_id: accountId
        }, function () {
            // Force an immediate status refresh so the button doesn't stay
            // stuck on "Wird abgebrochen..." if the sync already finished or
            // responds late. The poll handles the transition to stopped/complete.
            self._pollSyncStatus(accountId);
        });
    },

    _pollSyncStatus: function (accountId) {
        var self = this;
        if (this._syncPollTimer) {
            clearTimeout(this._syncPollTimer);
        }

        this.appWin.apiRequest("sync", {
            action: "status",
            account_id: accountId
        }, function (success, data) {
            if (!success || !data) return;

            var syncing = (data.status === "syncing" || data.status === "starting");

            // Only push the syncing flag to settings + albums if we are
            // still viewing the account that this poll belongs to.
            // Otherwise switching to account B while account A syncs
            // would lock B's UI.
            var isCurrentAccount = self.currentAccountData && self.currentAccountData.id === accountId;
            if (isCurrentAccount && self.appWin && self.appWin.detailPanel) {
                var dp = self.appWin.detailPanel;
                if (dp.settingsTab && dp.settingsTab.setSyncRunning) {
                    dp.settingsTab.setSyncRunning(syncing);
                }
                if (dp.albumTab && dp.albumTab.setSyncRunning) {
                    dp.albumTab.setSyncRunning(syncing);
                }
            }

            // Show "Nächster Sync" in the subtitle when not actively syncing
            if (!syncing && data.next_scheduled_run) {
                var subEl = Ext.get("ics-ov-subtitle");
                if (subEl) {
                    var now = Math.floor(Date.now() / 1000);
                    var diff = data.next_scheduled_run - now;
                    var whenText;
                    if (diff <= 60) {
                        whenText = SYNO.SDS.iCloudPhotoSync._T("overview:timing_soon");
                    } else if (diff < 3600) {
                        whenText = SYNO.SDS.iCloudPhotoSync._T("overview:timing_minutes", [Math.round(diff / 60)]);
                    } else if (diff < 86400) {
                        var h = Math.floor(diff / 3600);
                        var m = Math.round((diff % 3600) / 60);
                        whenText = SYNO.SDS.iCloudPhotoSync._T("overview:timing_hours", [h, m]);
                    } else {
                        var dt = new Date(data.next_scheduled_run * 1000);
                        whenText = dt.toLocaleDateString("de-DE") + " " + dt.toLocaleTimeString("de-DE", {hour: "2-digit", minute: "2-digit"});
                    }
                    var existingHtml = subEl.dom.innerHTML || "";
                    var marker = SYNO.SDS.iCloudPhotoSync._T("overview:label_next_sync");
                    if (existingHtml.indexOf(marker) === -1) {
                        subEl.dom.innerHTML = existingHtml + '<br><span style="color:#888;font-size:12px;">' + marker + ' ' + Ext.util.Format.htmlEncode(whenText) + '</span>';
                    }
                }
            }

            if (syncing) {
                var processed = (data.synced_photos || 0) + (data.skipped_photos || 0) + (data.failed_photos || 0);
                var pct = 0;
                var progressText = "";
                var statusMsg = SYNO.SDS.iCloudPhotoSync._T("overview:status_files_syncing");
                var fullLibraryProgress = data.total_photos_exact === false;
                var totalKnown = !fullLibraryProgress;
                var failed = data.failed_photos || 0;
                if (!totalKnown) {
                    if (failed > 0) {
                        progressText = SYNO.SDS.iCloudPhotoSync._T("overview:progress_discovered_files_failed", [processed, failed]);
                    } else {
                        progressText = SYNO.SDS.iCloudPhotoSync._T("overview:progress_discovered_files", [processed]);
                    }
                    if (data.current_album) progressText += " (" + data.current_album + ")";
                    statusMsg = progressText;
                } else if (data.total_photos > 0) {
                    pct = Math.min(100, Math.round(processed * 100 / data.total_photos));
                    if (failed > 0) {
                        progressText = SYNO.SDS.iCloudPhotoSync._T("overview:progress_files_failed", [pct, processed, data.total_photos, failed]);
                    } else {
                        progressText = SYNO.SDS.iCloudPhotoSync._T("overview:progress_files", [pct, processed, data.total_photos]);
                    }
                    if (data.current_album) progressText += " (" + data.current_album + ")";
                    statusMsg = progressText;
                }
                // Keep the status card's subtitle empty — the progress bar
                // below holds the detailed state, so the subtitle duplicating
                // it is just noise.
                self._setSyncingState(SYNO.SDS.iCloudPhotoSync._T("overview:status_syncing"), "");
                self.appWin.statusBar.body.update(statusMsg);

                var progWrap = Ext.get("ics-sync-progress");
                if (progWrap) {
                    if (!totalKnown) {
                        progWrap.dom.style.display = "";
                        if (progWrap.dom.firstChild) {
                            progWrap.dom.firstChild.style.display = "none";
                        }
                        var unknownFill = progWrap.dom.querySelector(".ics-sync-progress-fill");
                        var unknownText = progWrap.dom.querySelector(".ics-sync-progress-text");
                        if (unknownFill) {
                            unknownFill.style.width = "0%";
                            unknownFill.style.opacity = "1";
                        }
                        if (unknownText) unknownText.innerHTML = Ext.util.Format.htmlEncode(progressText);
                    } else if (data.total_photos > 0) {
                        progWrap.dom.style.display = "";
                        if (progWrap.dom.firstChild) {
                            progWrap.dom.firstChild.style.display = "";
                        }
                        var fill = progWrap.dom.querySelector(".ics-sync-progress-fill");
                        var ptxt = progWrap.dom.querySelector(".ics-sync-progress-text");
                        if (fill) {
                            fill.style.width = pct + "%";
                            fill.style.opacity = "1";
                        }
                        if (ptxt) ptxt.innerHTML = Ext.util.Format.htmlEncode(progressText);
                    } else {
                        progWrap.dom.style.display = "none";
                    }
                }
                self._syncPollTimer = setTimeout(function () {
                    self._pollSyncStatus(accountId);
                }, 3000);
            } else if (data.status === "complete") {
                self._stopRequested = false;
                var pw = Ext.get("ics-sync-progress"); if (pw) pw.dom.style.display = "none";
                var hasWarnings = (data.warnings && data.warnings.length > 0) || (data.failed_photos > 0);
                if (hasWarnings) {
                    var warnList = (data.warnings || []).slice();
                    if (data.failed_photos > 0 && warnList.length === 0) {
                        warnList.push(data.failed_photos + " file(s) failed");
                    }
                    self.appWin.statusBar.body.update(SYNO.SDS.iCloudPhotoSync._T("overview:status_complete_warnings"));
                    self._setWarningState(
                        SYNO.SDS.iCloudPhotoSync._T("overview:status_complete_warnings"),
                        warnList
                    );
                } else {
                    self.appWin.statusBar.body.update(SYNO.SDS.iCloudPhotoSync._T("status:ready"));
                    self._setIdleState(
                        SYNO.SDS.iCloudPhotoSync._T("overview:status_uptodate"),
                        SYNO.SDS.iCloudPhotoSync._T("overview:status_connected")
                    );
                }
                self._refreshStats(accountId);
            } else if (data.status === "error") {
                self._stopRequested = false;
                var pw2 = Ext.get("ics-sync-progress"); if (pw2) pw2.dom.style.display = "none";
                self._setErrorState(SYNO.SDS.iCloudPhotoSync._T("overview:status_error"), Ext.util.Format.htmlEncode(data.error));
                self.appWin.statusBar.body.update(SYNO.SDS.iCloudPhotoSync._T("overview:status_sync_failed"));
            } else if (data.status === "stopped") {
                self._stopRequested = false;
                var pw3 = Ext.get("ics-sync-progress"); if (pw3) pw3.dom.style.display = "none";
                self.appWin.statusBar.body.update(SYNO.SDS.iCloudPhotoSync._T("overview:status_sync_stopped"));
                self._setIdleState(
                    SYNO.SDS.iCloudPhotoSync._T("overview:status_sync_stopped"),
                    SYNO.SDS.iCloudPhotoSync._T("overview:status_connected")
                );
                self._refreshStats(accountId);
            }
        });
    },

    _pollMoveStatus: function (accountId, quietIfIdle) {
        var self = this;
        if (this._movePollTimer) clearTimeout(this._movePollTimer);

        this.appWin.apiRequest("move", {
            action: "status",
            account_id: accountId
        }, function (success, data) {
            if (!success || !data) return;
            var moving = (data.status === "moving" || data.status === "starting");

            if (moving) {
                var processed = (data.moved_files || 0) + (data.failed_files || 0);
                var total = data.total_files || 0;
                var pct = total > 0 ? Math.min(100, Math.round(processed * 100 / total)) : 0;
                var txt = SYNO.SDS.iCloudPhotoSync._T("overview:status_move_preparing");
                if (total > 0) {
                    txt = SYNO.SDS.iCloudPhotoSync._T("overview:progress_moved_files", [pct, processed.toLocaleString("de-DE"), total.toLocaleString("de-DE")]);
                    if (data.current_file) {
                        txt += " (" + Ext.util.Format.htmlEncode(data.current_file) + ")";
                    }
                }
                self._setMovingState(SYNO.SDS.iCloudPhotoSync._T("overview:status_moving"), "");
                self.appWin.statusBar.body.update(txt);

                var progWrap = Ext.get("ics-sync-progress");
                if (progWrap) {
                    progWrap.dom.style.display = total > 0 ? "" : "none";
                    var fill = progWrap.dom.querySelector(".ics-sync-progress-fill");
                    var ptxt = progWrap.dom.querySelector(".ics-sync-progress-text");
                    if (fill) fill.style.width = pct + "%";
                    if (ptxt) ptxt.innerHTML = Ext.util.Format.htmlEncode(txt);
                }
                self._movePollTimer = setTimeout(function () {
                    self._pollMoveStatus(accountId);
                }, 2000);
            } else if (data.status === "complete") {
                self._moveStopRequested = false;
                var pw = Ext.get("ics-sync-progress"); if (pw) pw.dom.style.display = "none";
                if (!quietIfIdle) {
                    self.appWin.statusBar.body.update(SYNO.SDS.iCloudPhotoSync._T("overview:status_move_complete"));
                    SYNO.SDS.iCloudPhotoSync._showMsg(
                        SYNO.SDS.iCloudPhotoSync._T("overview:status_move_complete"),
                        SYNO.SDS.iCloudPhotoSync._T("overview:msg_files_moved", [(data.moved_files || 0).toLocaleString("de-DE")]) +
                        (data.failed_files ? "<br>" + SYNO.SDS.iCloudPhotoSync._T("overview:msg_move_errors", [data.failed_files]) : ""),
                        "info"
                    );
                }
                self._setIdleState(
                    SYNO.SDS.iCloudPhotoSync._T("overview:status_uptodate"),
                    SYNO.SDS.iCloudPhotoSync._T("overview:status_connected")
                );
                self._refreshStats(accountId);
            } else if (data.status === "error") {
                self._moveStopRequested = false;
                var pw2 = Ext.get("ics-sync-progress"); if (pw2) pw2.dom.style.display = "none";
                if (!quietIfIdle) {
                    self._setErrorState(SYNO.SDS.iCloudPhotoSync._T("overview:error_move_failed"),
                        Ext.util.Format.htmlEncode(data.error || ""));
                }
            } else if (data.status === "stopped") {
                self._moveStopRequested = false;
                var pw3 = Ext.get("ics-sync-progress"); if (pw3) pw3.dom.style.display = "none";
                if (!quietIfIdle) {
                    self.appWin.statusBar.body.update(SYNO.SDS.iCloudPhotoSync._T("overview:status_move_cancelled"));
                }
                self._setIdleState(
                    SYNO.SDS.iCloudPhotoSync._T("overview:status_uptodate"),
                    SYNO.SDS.iCloudPhotoSync._T("overview:status_connected")
                );
                self._refreshStats(accountId);
            }
        });
    },

    _setMovingState: function (title, subtitle) {
        var self = this;
        var iconEl = this.body.dom.querySelector(".ics-status-icon");
        var titleEl = this.body.dom.querySelector(".ics-status-title");
        var subtitleEl = Ext.get("ics-ov-subtitle");
        var syncBtn = Ext.get("ics-sync-now-btn");
        var stopBtn = Ext.get("ics-stop-sync-btn");

        if (iconEl) iconEl.className = "ics-status-icon ics-icon-syncing";
        if (titleEl) titleEl.innerHTML = title;
        if (subtitleEl) subtitleEl.update(subtitle);

        var progEl = Ext.get("ics-sync-progress");
        if (!progEl) {
            var btnRow = this.body.dom.querySelector(".ics-ov-btn-row");
            if (btnRow && btnRow.parentNode) {
                var wrap = document.createElement("div");
                wrap.id = "ics-sync-progress";
                wrap.style.cssText = "margin:8px 0;display:none;";
                wrap.innerHTML =
                    '<div style="background:#e5e7eb;border-radius:4px;height:8px;overflow:hidden;">' +
                      '<div class="ics-sync-progress-fill" style="background:#2a84ff;height:100%;width:0%;transition:width .3s;"></div>' +
                    '</div>' +
                    '<div class="ics-sync-progress-text" style="font-size:12px;color:#888;margin-top:4px;"></div>';
                btnRow.parentNode.insertBefore(wrap, btnRow);
            }
        }

        if (syncBtn) syncBtn.dom.style.display = "none";
        if (!stopBtn) {
            var container = this.body.dom.querySelector(".ics-ov-btn-row");
            if (container) {
                var stopHtml = '<a href="#" id="ics-stop-sync-btn" class="ics-ov-action-btn ics-btn-red">' + SYNO.SDS.iCloudPhotoSync._T("overview:btn_stop_sync") + '</a>';
                var tmpEl = document.createElement("span");
                tmpEl.innerHTML = stopHtml;
                container.appendChild(tmpEl.firstChild);
                stopBtn = Ext.get("ics-stop-sync-btn");
            }
        }
        if (stopBtn) {
            stopBtn.dom.style.display = "";
            if (this._moveStopRequested) {
                stopBtn.dom.innerHTML = SYNO.SDS.iCloudPhotoSync._T("overview:status_stopping");
                stopBtn.dom.className = "ics-ov-action-btn ics-btn-disabled";
            } else {
                stopBtn.removeAllListeners();
                stopBtn.on("click", function (e) {
                    e.preventDefault();
                    self._stopMove();
                });
            }
        }
    },

    _stopMove: function () {
        var self = this;
        if (!this.currentAccountData) return;
        var accountId = this.currentAccountData.id;
        this._moveStopRequested = true;
        var stopBtn = Ext.get("ics-stop-sync-btn");
        if (stopBtn) {
            stopBtn.dom.innerHTML = SYNO.SDS.iCloudPhotoSync._T("overview:status_stopping");
            stopBtn.dom.className = "ics-ov-action-btn ics-btn-disabled";
            stopBtn.removeAllListeners();
        }
        this.appWin.apiRequest("move", {
            action: "stop",
            account_id: accountId
        }, function () {
            self._pollMoveStatus(accountId);
        });
    }
});

// --- Album Tab (List + Photo Grid) ---
Ext.define("SYNO.SDS.iCloudPhotoSync.AlbumGrid", {
    extend: "Ext.Panel",

    constructor: function (config) {
        var self = this;
        this.currentAccountId = null;
        this.syncConfig = {};  // loaded sync config for current account

        // Structured data from API: { libraries: [...] }
        this._treeData = { libraries: [] };
        this._collapsedLibraries = {};

        // Album list store — flat rows including library_header separators
        this.albumStore = new Ext.data.JsonStore({
            fields: ["name", "type", "photo_count", "parent_folder", "library", {name: "sync_enabled", type: "boolean", defaultValue: false}],
            data: []
        });

        // Album list (left side) with sync checkbox
        this.albumListView = new Ext.grid.GridPanel({
            store: this.albumStore,
            hideHeaders: true,
            cls: "ics-album-grid",
            columns: [
                {
                    id: "ics-sync-check",
                    dataIndex: "sync_enabled",
                    width: 30,
                    renderer: function (val, meta, record) {
                        if (record.get("type") === "library_header") return "";
                        if (record.get("type") === "folder") {
                            var state = self._getFolderCheckState(self._folderPath(record), record.get("library"));
                            var cls = state === "all" ? "syno-ux-checkbox-checked"
                                    : state === "some" ? "syno-ux-checkbox-indeterminate"
                                    : "syno-ux-checkbox";
                            return '<div class="' + cls + '" style="width: 16px; height: 16px; margin: 2px auto 0;"></div>';
                        }
                        var cls = val ? "syno-ux-checkbox-checked" : "syno-ux-checkbox";
                        return '<div class="' + cls + '" style="width: 16px; height: 16px; margin: 2px auto 0;"></div>';
                    }
                },
                {
                    dataIndex: "name", id: "ics-album-name",
                    renderer: function (val, meta, record) {
                        var type = record.get("type");
                        if (type === "library_header") {
                            var libId = record.get("library");
                            var collapsed = !!self._collapsedLibraries[libId];
                            var arrowCls = "ics-library-arrow" + (collapsed ? " collapsed" : "");
                            meta.attr = 'style="padding: 0;"';
                            return '<div style="font-weight: 600; font-size: 13px; padding: 6px 0;">' +
                                   '<span class="' + arrowCls + '">▼</span>' +
                                   '<img src="/webman/3rdparty/iCloudPhotoSync/images/applephotos.png" style="width:16px;height:16px;vertical-align:middle;margin-right:6px;" />' +
                                   Ext.util.Format.htmlEncode(val) + '</div>';
                        }
                        var parentFolder = record.get("parent_folder") || "";
                        var depth = parentFolder ? parentFolder.split("/").length : 0;
                        var icon = type === "shared" ? "👥" : type === "smart" ? "☆" : "📁";
                        var count = record.get("photo_count");
                        var countStr = type === "folder" ? ""
                            : (count < 0) ? '<span style="color: #ccc;">…</span>'
                            : count.toLocaleString("de-DE");
                        var indent = depth > 0 ? "padding-left: " + (depth * 20) + "px; " : "";
                        return '<span style="' + indent + 'font-size: 13px; line-height: 22px;">' + icon + ' ' +
                               Ext.util.Format.htmlEncode(val) +
                               '</span><span style="float: right; color: #999; font-size: 12px; line-height: 22px;">' +
                               countStr + '</span>';
                    }
                }
            ],
            autoExpandColumn: "ics-album-name",
            border: false,
            listeners: {
                cellclick: function (grid, rowIndex, colIndex, e) {
                    var record = self.albumStore.getAt(rowIndex);
                    if (!record) return;
                    if (record.get("type") === "library_header") {
                        var libId = record.get("library");
                        self._collapsedLibraries[libId] = !self._collapsedLibraries[libId];
                        self._refreshGrid();
                        return;
                    }
                    // Column 0 = checkbox
                    if (colIndex === 0) {
                        if (self._syncRunning) return;
                        if (record.get("type") === "folder") {
                            self._toggleFolderSync(self._folderPath(record), record.get("library"));
                            return;
                        }
                        var newVal = !record.get("sync_enabled");
                        record.set("sync_enabled", newVal);
                        record.commit();
                        self._toggleAlbumSync(record.get("name"), newVal, record.get("type"), record.get("library"));
                        self._refreshFolderCheckboxes(record.get("parent_folder"), record.get("library"));
                    } else {
                        if (record.get("type") === "folder") return;
                        self._selectedAlbum = record.get("name");
                        self._selectedLibrary = record.get("library");
                        self.loadPhotos(record.get("name"), record.get("library"));
                    }
                }
            }
        });

        // Photo thumbnail area with top toolbar (sort) and bottom bar (size slider).
        this.photoSortCombo = new SYNO.ux.ComboBox({
            store: new Ext.data.ArrayStore({
                fields: ["val", "label"],
                data: [["DESCENDING", SYNO.SDS.iCloudPhotoSync._T("album:sort_newest")], ["ASCENDING", SYNO.SDS.iCloudPhotoSync._T("album:sort_oldest")]]
            }),
            displayField: "label", valueField: "val",
            mode: "local", triggerAction: "all", editable: false,
            value: "DESCENDING", width: 160,
            listeners: {
                select: function () {
                    if (self._photoView && self._photoView.album) {
                        self.loadPhotos(self._photoView.album, self._photoView.libraryId);
                    }
                }
            }
        });

        this._thumbSize = 120;
        this.photoSizeSlider = new Ext.BoxComponent({
            width: 150, height: 22,
            autoEl: {
                tag: "input", type: "range",
                min: "60", max: "240", step: "20", value: "120",
                style: "width:150px;vertical-align:middle;cursor:pointer;"
            },
            listeners: {
                afterrender: function (c) {
                    c.el.on("input", function () {
                        var v = parseInt(c.el.dom.value, 10) || 120;
                        self._thumbSize = v;
                        self._applyThumbSize(v);
                    });
                }
            }
        });
        this.photoSizeSlider.getValue = function () { return self._thumbSize; };

        // Cross-album cart. Keyed by photo.id -- each entry captures everything
        // we need to export later, independent of which album is currently open.
        this._cart = {};

        this.cartBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("album:btn_cart_empty"),
            cls: "ics-cart-btn",
            disabled: true,
            handler: function () { self._openCart(); }
        });
        this.clearCartBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("album:btn_clear_cart"),
            disabled: true,
            handler: function () { self._clearCart(); }
        });

        this.photoPanel = new Ext.Panel({
            region: "center",
            autoScroll: true,
            border: false,
            bodyStyle: "padding: 8px; background: #f9f9f9;",
            tbar: [
                { xtype: "tbspacer", width: 4 },
                this.cartBtn,
                this.clearCartBtn,
                "->",
                { xtype: "tbtext", text: SYNO.SDS.iCloudPhotoSync._T("album:label_sort"), style: "padding-right:6px;" },
                this.photoSortCombo,
                { xtype: "tbspacer", width: 4 }
            ],
            bbar: [
                "->",
                { xtype: "tbtext", text: SYNO.SDS.iCloudPhotoSync._T("album:label_size"), style: "padding-right:6px;" },
                this.photoSizeSlider
            ],
            html: '<div style="text-align: center; padding: 40px; color: #999;">' + SYNO.SDS.iCloudPhotoSync._T("album:empty_state") + '</div>'
        });

        // View state for lazy-loading.
        this._photoView = null;
        this._photoViewGen = 0;

        // Inline banner shown while a sync is running. The album sync toggle
        // is rejected by the backend during a sync, so we surface that here.
        // Fixed height + explicit show/hide via setHeight so the layout below
        // doesn't keep an empty gap when the banner disappears.
        this.syncBlockedBanner = new Ext.Panel({
            border: false,
            hidden: true,
            height: 36,
            bodyStyle: "background:#fff3cd;border-bottom:1px solid #f0ad4e;padding:8px 14px;font-size:13px;color:#7a5d00;overflow:hidden;",
            html: SYNO.SDS.iCloudPhotoSync._T("album:banner_sync_blocked")
        });

        // Progress bar (indeterminate, hidden by default)
        this.progressBar = new Ext.Panel({
            height: 3,
            border: false,
            bodyStyle: "overflow: hidden; background: transparent;",
            html: ''
        });

        // Inject progress bar animation
        if (!document.getElementById("ics-progress-style")) {
            var pStyle = document.createElement("style");
            pStyle.id = "ics-progress-style";
            pStyle.textContent = "@keyframes ics-progress { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }";
            document.head.appendChild(pStyle);
        }

        // Outer layout: vbox so the banner can sit at full width above the
        // album/photo split without taking permanent space when hidden.
        // The inner border-layout container holds album list + photo panel.
        this.albumSplit = new Ext.Container({
            flex: 1,
            layout: "border",
            border: false,
            items: [
                this.progressBar,
                {
                    region: "west",
                    width: 280,
                    split: true,
                    layout: "fit",
                    border: false,
                    items: [this.albumListView]
                },
                this.photoPanel
            ]
        });
        // progressBar already has region; explicitly mark for border layout.
        this.progressBar.region = "north";

        var cfg = Ext.apply({
            title: SYNO.SDS.iCloudPhotoSync._T("tab:albums"),
            layout: "vbox",
            layoutConfig: { align: "stretch" },
            border: false,
            items: [this.syncBlockedBanner, this.albumSplit]
        }, config);

        delete cfg.appWin;
        this.appWin = config.appWin;
        this.callParent([cfg]);
    },

    setSyncRunning: function (running) {
        if (this._syncRunning === running) return;
        this._syncRunning = running;
        if (this.syncBlockedBanner && this.syncBlockedBanner.setVisible) {
            this.syncBlockedBanner.setVisible(running);
        }
        if (this.doLayout) this.doLayout();
        var el = this.albumListView && this.albumListView.getEl && this.albumListView.getEl();
        if (el) {
            if (running) el.addClass("ics-album-grid-readonly");
            else el.removeClass("ics-album-grid-readonly");
        }
    },

    showProgress: function () {
        if (this.progressBar.body) {
            this.progressBar.body.update('<div style="height: 3px; background: linear-gradient(90deg, #057feb 0%, #6aadea 50%, #057feb 100%); background-size: 200% 100%; animation: ics-progress 1.2s linear infinite;"></div>');
        }
    },

    hideProgress: function () {
        if (this.progressBar.body) {
            this.progressBar.body.update('');
        }
    },

    // ── Grid data building ────────────────────────────────────────────

    _buildStoreData: function () {
        var data = this._treeData;
        var rows = [];
        var libs = data.libraries || [];

        for (var li = 0; li < libs.length; li++) {
            var lib = libs[li];
            var libName = lib.id === "shared"
                ? SYNO.SDS.iCloudPhotoSync._T("album:library_shared")
                : SYNO.SDS.iCloudPhotoSync._T("album:library_personal");
            rows.push({ name: libName, type: "library_header", photo_count: -1, parent_folder: "", library: lib.id, sync_enabled: false });
            if (!this._collapsedLibraries[lib.id]) {
                var albums = lib.albums || [];
                for (var i = 0; i < albums.length; i++) {
                    var a = albums[i];
                    rows.push({
                        name: a.name, type: a.type, photo_count: a.photo_count,
                        parent_folder: a.parent_folder || "", library: lib.id,
                        sync_enabled: this._isAlbumSyncEnabled(a.name, lib.id)
                    });
                }
            }
        }
        return rows;
    },

    _refreshGrid: function () {
        var self = this;
        var scrollTop = this.albumListView.body ? this.albumListView.body.dom.scrollTop : 0;
        var rows = this._buildStoreData();

        this.albumStore.loadData(rows);
        this._applyHeaderStyles(rows);
        // Deferred re-apply in case the view wasn't ready synchronously
        (function () {
            var r = rows;
            setTimeout(function () { self._applyHeaderStyles(r); }, 50);
        })();
        if (this.albumListView.body) this.albumListView.body.dom.scrollTop = scrollTop;
    },

    _applyHeaderStyles: function (rows) {
        var view = this.albumListView.getView();
        if (!view) return;
        for (var i = 0; i < rows.length; i++) {
            if (rows[i].type === "library_header") {
                var rowEl = view.getRow(i);
                if (!rowEl) continue;
                Ext.fly(rowEl).addClass("ics-library-header");
                var cells = rowEl.getElementsByTagName("td");
                if (cells.length >= 2) {
                    cells[0].style.display = "none";
                    cells[1].colSpan = 2;
                }
            }
        }
    },

    _updateStoreCount: function (albumName, libraryId, count) {
        var idx = this.albumStore.findBy(function (r) {
            return r.get("name") === albumName && r.get("library") === libraryId && r.get("type") !== "library_header";
        });
        if (idx >= 0) {
            this.albumStore.getAt(idx).set("photo_count", count);
            this.albumStore.getAt(idx).commit();
        }
    },

    _folderPath: function (record) {
        var parent = record.get("parent_folder") || "";
        return parent ? parent + "/" + record.get("name") : record.get("name");
    },

    _toggleFolderSync: function (folderPath, libraryId) {
        var state = this._getFolderCheckState(folderPath, libraryId);
        var newVal = state !== "all";
        this.albumStore.each(function (record) {
            if (record.get("parent_folder") === folderPath && record.get("library") === libraryId && record.get("type") !== "folder") {
                record.set("sync_enabled", newVal);
                record.commit();
                this._setAlbumSyncEnabled(record.get("name"), libraryId, newVal);
                this._toggleAlbumSync(record.get("name"), newVal, record.get("type"), libraryId);
            }
        }, this);
        this._refreshFolderCheckboxes(folderPath, libraryId);
    },

    _refreshFolderCheckboxes: function (folderPath, libraryId) {
        if (!folderPath) return;
        var self = this;
        var view = this.albumListView.getView();
        if (!view) return;
        var idx = this.albumStore.findBy(function (r) {
            return r.get("type") === "folder" && r.get("library") === libraryId
                && self._folderPath(r) === folderPath;
        });
        if (idx >= 0) view.refreshRow(idx);
        var slash = folderPath.lastIndexOf("/");
        if (slash > 0) {
            this._refreshFolderCheckboxes(folderPath.substring(0, slash), libraryId);
        }
    },

    _getFolderCheckState: function (folderPath, libraryId) {
        var albums = this._getLibraryAlbums(libraryId);
        var total = 0, enabled = 0;
        for (var i = 0; i < albums.length; i++) {
            if (albums[i].parent_folder === folderPath && albums[i].type !== "folder") {
                total++;
                if (this._isAlbumSyncEnabled(albums[i].name, libraryId)) enabled++;
            }
        }
        if (total === 0 || enabled === 0) return "none";
        if (enabled === total) return "all";
        return "some";
    },

    // ── Sync state helpers ──────────────────────────────────────────

    _isAlbumSyncEnabled: function (albumName, libraryId) {
        var cfg = this.syncConfig;
        if (libraryId === "shared") {
            return !!((cfg.shared_library && cfg.shared_library.selected || {})[albumName]);
        }
        return !!((cfg.albums && cfg.albums.selected || {})[albumName]);
    },

    _setAlbumSyncEnabled: function (albumName, libraryId, enabled) {
        var cfg = this.syncConfig;
        if (libraryId === "shared") {
            if (!cfg.shared_library) cfg.shared_library = {};
            if (!cfg.shared_library.selected) cfg.shared_library.selected = {};
            cfg.shared_library.selected[albumName] = enabled;
        } else {
            if (!cfg.albums) cfg.albums = {};
            if (!cfg.albums.selected) cfg.albums.selected = {};
            cfg.albums.selected[albumName] = enabled;
        }
    },

    _getLibraryAlbums: function (libraryId) {
        var libs = this._treeData.libraries || [];
        for (var i = 0; i < libs.length; i++) {
            if (libs[i].id === libraryId) return libs[i].albums || [];
        }
        return [];
    },

    _toggleAlbumSync: function (albumName, enabled, albumType, libraryId) {
        if (!this.currentAccountId) return;
        var self = this;
        var reqParams = {
            action: "set_album",
            account_id: this.currentAccountId,
            album: albumName,
            enabled: enabled ? "true" : "false"
        };
        if (albumType === "shared") reqParams.album_type = "shared";
        if (libraryId === "shared") reqParams.library = "shared";
        this.appWin.apiRequest("config", reqParams, function (success, data, errMsg) {
            if (!success) {
                self._setAlbumSyncEnabled(albumName, libraryId, !enabled);
                self._refreshGrid();
                SYNO.SDS.iCloudPhotoSync._showMsg(
                    SYNO.SDS.iCloudPhotoSync._T("album:error_title"),
                    errMsg || SYNO.SDS.iCloudPhotoSync._T("album:error_save_failed"),
                    "info"
                );
            }
        }, true);
    },

    _applySyncConfig: function () {
        this._refreshGrid();
    },

    loadAlbums: function (accountId) {
        var self = this;
        this.currentAccountId = accountId;
        this.albumStore.removeAll();
        this._treeData = { libraries: [] };
        this._refreshGrid();
        this.showProgress();

        // Load sync config for this account
        this.appWin.apiRequest("config", {
            action: "get",
            account_id: accountId
        }, function (success, data) {
            if (success && data) {
                self.syncConfig = data;
            }
        });

        // Step 1: Try loading from local cache first (instant, no Apple API)
        this.appWin.apiRequest("album", {
            action: "cached",
            account_id: accountId
        }, function (success, data) {
            if (success && data.libraries && data.libraries.length > 0) {
                self._treeData = { libraries: data.libraries };
                self._applySyncConfig();
                self.hideProgress();
                var totalAlbums = (data.albums || []).length;
                self.photoPanel.body.update(
                    '<div style="text-align: center; padding: 40px; color: #999;">' +
                    SYNO.SDS.iCloudPhotoSync._T("album:empty_count", [totalAlbums]) +
                    '</div>'
                );
            }

            // Step 2: Refresh from Apple API in background
            self._refreshFromApi(accountId);
        });
    },

    _refreshFromApi: function (accountId) {
        var self = this;
        var hadCache = (this._treeData.libraries || []).length > 0;
        if (!hadCache) self.showProgress();

        this.appWin.apiRequest("album", {
            action: "list",
            account_id: accountId
        }, function (success, data, errMsg, errObj) {

            if (success && data.libraries) {
                self._treeData = { libraries: data.libraries };
                self._applySyncConfig();
                if (!hadCache) {
                    var totalAlbums = (data.albums || []).length;
                    self.photoPanel.body.update(
                        '<div style="text-align: center; padding: 40px; color: #999;">' +
                        SYNO.SDS.iCloudPhotoSync._T("album:empty_count", [totalAlbums]) +
                        '</div>'
                    );
                }
                // Refresh counts in background
                self._loadAlbumCounts(data.albums || [], 0);
            } else {
                self.hideProgress();
                var isADP = errObj && errObj.code === 320;
                var html;
                if (isADP) {
                    html = '<div style="text-align: center; padding: 40px;">' +
                        '<div style="display: inline-block; max-width: 520px; text-align: left; background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; padding: 16px 20px;">' +
                        '<div style="font-weight: bold; font-size: 14px; margin-bottom: 8px; color: #856404;">' +
                        Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("album:adp_title")) +
                        '</div>' +
                        '<div style="font-size: 13px; color: #856404; line-height: 1.5;">' +
                        Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("album:adp_message")) +
                        '</div></div></div>';
                } else if (!hadCache) {
                    html = '<div style="text-align: center; padding: 40px; color: #c00;">' +
                        Ext.util.Format.htmlEncode(errMsg || SYNO.SDS.iCloudPhotoSync._T("album:error_load_failed")) +
                        '</div>';
                }
                if (html) {
                    self.photoPanel.body.update(html);
                }
            }
        });
    },

    _loadAlbumCounts: function (albums, index) {
        var self = this;
        // Build a flat list of all albums with their library context
        if (!this._countQueue) {
            this._countQueue = [];
            var libs = this._treeData.libraries || [];
            for (var li = 0; li < libs.length; li++) {
                var libAlbums = libs[li].albums || [];
                for (var ai = 0; ai < libAlbums.length; ai++) {
                    if (libAlbums[ai].type !== "folder") {
                        this._countQueue.push({ name: libAlbums[ai].name, library: libs[li].id, _ref: libAlbums[ai] });
                    }
                }
            }
        }
        if (index >= this._countQueue.length) {
            this.hideProgress();
            this._countQueue = null;
            return;
        }

        var item = this._countQueue[index];
        var reqParams = {
            action: "count",
            account_id: this.currentAccountId,
            album: item.name
        };
        if (item.library && item.library !== "personal") reqParams.library = item.library;
        this.appWin.apiRequest("album", reqParams, function (success, data) {
            if (success && data.photo_count !== undefined) {
                item._ref.photo_count = data.photo_count;
                self._updateStoreCount(item.name, item.library, data.photo_count);
            }
            self._loadAlbumCounts(albums, index + 1);
        });
    },

    // Page size for lazy-load. Sticks to the same batch CloudKit tends to
    // return (~100 pair cap) so we rarely get partial pages.
    PAGE_SIZE: 100,

    _thumbSizePx: function () {
        return (this.photoSizeSlider && this.photoSizeSlider.getValue()) || 120;
    },

    _applyThumbSize: function (px) {
        // Re-size existing thumbnails in place; new ones picked up on next append.
        var grid = this.photoPanel.body.dom.querySelector(".ics-thumb-grid");
        if (!grid) return;
        var h = Math.round(px * 0.75);
        var tiles = grid.querySelectorAll(".ics-thumb-tile");
        for (var i = 0; i < tiles.length; i++) {
            tiles[i].style.width = px + "px";
            var img = tiles[i].querySelector(".ics-thumb-img");
            if (img) { img.style.width = px + "px"; img.style.height = h + "px"; }
            var ph = tiles[i].querySelector(".ics-thumb-ph");
            if (ph) { ph.style.width = px + "px"; ph.style.height = h + "px"; }
        }
    },

    _renderThumb: function (photo, px, idx) {
        var proxyBase = "/webman/3rdparty/iCloudPhotoSync/api.cgi?method=thumb&url=";
        var thumbUrl = photo.thumb_url ? proxyBase + encodeURIComponent(photo.thumb_url) : "";
        var title = Ext.util.Format.htmlEncode(photo.filename || "");
        var sizeKB = photo.size ? Math.round(photo.size / 1024) : 0;
        var dims = (photo.width && photo.height) ? photo.width + "\u00d7" + photo.height : "";
        var tooltip = title + (dims ? " (" + dims + ")" : "") + (sizeKB ? " " + sizeKB + " KB" : "");
        var h = Math.round(px * 0.75);
        var selected = this._cart && photo.id && this._cart[photo.id];
        var borderColor = selected ? "#057feb" : "#e0e0e0";
        var checkBg = selected ? "#057feb" : "rgba(255,255,255,0.85)";
        var checkColor = selected ? "#fff" : "transparent";

        var html = '<div class="ics-thumb-tile' + (selected ? ' ics-selected' : '') + '" data-idx="' + idx + '" style="position:relative;width:' + px + 'px;text-align:center;background:#fff;border:2px solid ' + borderColor + ';border-radius:4px;overflow:hidden;cursor:pointer;" title="' + tooltip + '">';
        if (thumbUrl) {
            html += '<img class="ics-thumb-img" src="' + thumbUrl + '" style="width:' + px + 'px;height:' + h + 'px;object-fit:cover;display:block;" onerror="this.style.display=\'none\'" />';
        } else {
            html += '<div class="ics-thumb-ph" style="width:' + px + 'px;height:' + h + 'px;background:#eee;display:flex;align-items:center;justify-content:center;color:#aaa;font-size:24px;">' +
                    (photo.is_video ? '\u25b6' : '\ud83d\uddbc') + '</div>';
        }
        html += '<div class="ics-thumb-check" data-action="select" style="position:absolute;top:6px;left:6px;width:22px;height:22px;border-radius:11px;background:' + checkBg + ';border:1px solid #888;color:' + checkColor + ';display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:bold;line-height:1;cursor:pointer;user-select:none;">\u2713</div>';
        html += '<div style="padding:4px;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#555;">' + title + '</div>';
        html += '</div>';
        return html;
    },

    _toggleSelect: function (idx) {
        var v = this._photoView;
        if (!v) return;
        var p = v.photos[idx];
        if (!p || !p.id) return;
        if (this._cart[p.id]) {
            delete this._cart[p.id];
        } else {
            this._cart[p.id] = {
                id: p.id,
                url: p.original_url || p.medium_url,
                filename: p.filename || ("photo_" + p.id + ".jpg"),
                thumb_url: p.thumb_url,
                album: v.album,
                width: p.width,
                height: p.height,
                size: p.size,
                is_video: p.is_video
            };
        }
        this._refreshTileSelection(idx);
        this._updateCartToolbar();
    },

    _refreshTileSelection: function (idx) {
        var v = this._photoView;
        if (!v) return;
        var tile = this.photoPanel.body.dom.querySelector('.ics-thumb-tile[data-idx="' + idx + '"]');
        if (!tile) return;
        var p = v.photos[idx];
        var sel = p && p.id && this._cart[p.id];
        tile.style.borderColor = sel ? "#057feb" : "#e0e0e0";
        var chk = tile.querySelector(".ics-thumb-check");
        if (chk) {
            chk.style.background = sel ? "#057feb" : "rgba(255,255,255,0.85)";
            chk.style.color = sel ? "#fff" : "transparent";
        }
    },

    _updateCartToolbar: function () {
        var n = Object.keys(this._cart || {}).length;
        if (this.cartBtn) {
            this.cartBtn.setText(n > 0
                ? SYNO.SDS.iCloudPhotoSync._T("album:btn_cart", [n])
                : SYNO.SDS.iCloudPhotoSync._T("album:btn_cart_empty"));
            this.cartBtn.setDisabled(n === 0);
        }
        if (this.clearCartBtn) this.clearCartBtn.setDisabled(n === 0);
    },

    _refreshAllTiles: function () {
        var tiles = this.photoPanel.body.dom.querySelectorAll(".ics-thumb-tile");
        for (var i = 0; i < tiles.length; i++) {
            var idx = parseInt(tiles[i].getAttribute("data-idx"), 10);
            if (!isNaN(idx)) this._refreshTileSelection(idx);
        }
    },

    _removeFromCart: function (id) {
        if (this._cart[id]) {
            delete this._cart[id];
            this._refreshAllTiles();
            this._updateCartToolbar();
        }
    },

    _clearCart: function () {
        this._cart = {};
        this._refreshAllTiles();
        this._updateCartToolbar();
    },

    _triggerBrowserDownload: function (url) {
        var a = document.createElement("a");
        a.href = url;
        a.style.display = "none";
        document.body.appendChild(a);
        a.click();
        setTimeout(function () { document.body.removeChild(a); }, 1000);
    },

    _downloadPhoto: function (photo) {
        var url = photo.original_url || photo.medium_url || photo.url;
        if (!url) return;
        var q = "/webman/3rdparty/iCloudPhotoSync/api.cgi?method=download" +
                "&url=" + encodeURIComponent(url) +
                "&filename=" + encodeURIComponent(photo.filename || "photo.jpg");
        this._triggerBrowserDownload(q);
    },

    _exportCart: function (onDone) {
        var ids = Object.keys(this._cart || {});
        if (!ids.length) return;
        var items = [];
        for (var i = 0; i < ids.length; i++) {
            var e = this._cart[ids[i]];
            if (!e || !e.url) continue;
            items.push({ url: e.url, filename: e.filename });
        }
        if (!items.length) return;

        var zipname = "iCloud_export.zip";
        var self = this;

        fetch("/webman/3rdparty/iCloudPhotoSync/api.cgi?method=download_zip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ items: items, zipname: zipname })
        }).then(function (r) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            var failedHeader = r.headers.get("X-Export-Failed") || "";
            return r.blob().then(function (blob) {
                return { blob: blob, failed: failedHeader };
            });
        }).then(function (res) {
            var url = URL.createObjectURL(res.blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = zipname;
            document.body.appendChild(a);
            a.click();
            setTimeout(function () {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 1000);
            if (res.failed) {
                var n = res.failed.split(",").filter(Boolean).length;
                if (n > 0) {
                    SYNO.SDS.iCloudPhotoSync._showDialog({
                        level: "error",
                        title: SYNO.SDS.iCloudPhotoSync._T("common:error"),
                        msg: SYNO.SDS.iCloudPhotoSync._T("album:export_partial", [n])
                    });
                }
            }
            if (onDone) onDone(true);
        }).catch(function (e) {
            SYNO.SDS.iCloudPhotoSync._showDialog({
                level: "error",
                title: SYNO.SDS.iCloudPhotoSync._T("common:error"),
                msg: SYNO.SDS.iCloudPhotoSync._T("album:export_failed") + " " + (e.message || "")
            });
            if (onDone) onDone(false);
        });
    },

    _openCart: function () {
        var self = this;
        var proxyBase = "/webman/3rdparty/iCloudPhotoSync/api.cgi?method=thumb&url=";

        var buildHtml = function () {
            var ids = Object.keys(self._cart || {});
            if (!ids.length) {
                return '<div style="padding:40px;text-align:center;color:#888;">' +
                    Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("album:cart_empty")) +
                    '</div>';
            }
            var html = '<div class="ics-cart-grid" style="display:flex;flex-wrap:wrap;gap:10px;padding:10px;">';
            for (var i = 0; i < ids.length; i++) {
                var e = self._cart[ids[i]];
                var thumb = e.thumb_url ? proxyBase + encodeURIComponent(e.thumb_url) : "";
                var name = Ext.util.Format.htmlEncode(e.filename || "");
                var album = Ext.util.Format.htmlEncode(e.album || "");
                html += '<div class="ics-cart-tile" data-id="' + Ext.util.Format.htmlEncode(e.id) + '" style="width:160px;background:#fff;border:1px solid #e0e0e0;border-radius:4px;overflow:hidden;position:relative;">';
                if (thumb) {
                    html += '<img src="' + thumb + '" style="width:160px;height:120px;object-fit:cover;display:block;" />';
                } else {
                    html += '<div style="width:160px;height:120px;background:#eee;display:flex;align-items:center;justify-content:center;color:#aaa;font-size:24px;">' +
                            (e.is_video ? '\u25b6' : '\ud83d\uddbc') + '</div>';
                }
                html += '<div style="padding:6px 8px;font-size:11px;">' +
                        '<div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#333;" title="' + name + '">' + name + '</div>' +
                        '<div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#888;margin-top:2px;" title="' + album + '">' + album + '</div>' +
                        '</div>';
                html += '<div style="display:flex;border-top:1px solid #eee;">' +
                        '<div data-action="dl" style="flex:1;text-align:center;padding:6px 0;cursor:pointer;color:#057feb;font-size:11px;border-right:1px solid #eee;" title="' +
                          Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("album:btn_save")) + '">\u2b73</div>' +
                        '<div data-action="rm" style="flex:1;text-align:center;padding:6px 0;cursor:pointer;color:#d9534f;font-size:11px;" title="' +
                          Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("common:delete")) + '">\u2715</div>' +
                        '</div>';
                html += '</div>';
            }
            html += '</div>';
            return html;
        };

        var panel = new Ext.Panel({
            autoScroll: true,
            border: false,
            bodyStyle: "background:#fafafa;",
            html: buildHtml()
        });

        var refresh = function () {
            panel.body.update(buildHtml());
            bindClicks();
            self._updateCartToolbar();
            footerCount.setText(SYNO.SDS.iCloudPhotoSync._T("album:cart_count", [Object.keys(self._cart).length]));
            exportBtn.setDisabled(Object.keys(self._cart).length === 0);
            clearBtn.setDisabled(Object.keys(self._cart).length === 0);
        };

        var bindClicks = function () {
            var root = panel.body.dom;
            root.onclick = function (e) {
                var target = e.target.closest ? e.target.closest("[data-action]") : null;
                if (!target) return;
                var tile = target.closest(".ics-cart-tile");
                if (!tile) return;
                var id = tile.getAttribute("data-id");
                var entry = self._cart[id];
                if (!entry) return;
                var action = target.getAttribute("data-action");
                if (action === "rm") {
                    self._removeFromCart(id);
                    refresh();
                } else if (action === "dl") {
                    self._downloadPhoto(entry);
                }
            };
        };

        var exportBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("album:btn_export_all"),
            btnStyle: "blue",
            disabled: Object.keys(self._cart).length === 0,
            handler: function () {
                exportBtn.setDisabled(true);
                var orig = exportBtn.getText();
                exportBtn.setText(SYNO.SDS.iCloudPhotoSync._T("album:exporting"));
                self._exportCart(function () {
                    exportBtn.setText(orig);
                    exportBtn.setDisabled(Object.keys(self._cart).length === 0);
                });
            }
        });
        var clearBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("album:btn_clear_cart"),
            disabled: Object.keys(self._cart).length === 0,
            handler: function () {
                self._clearCart();
                refresh();
            }
        });
        var closeBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("common:close"),
            handler: function () { win.close(); }
        });
        var footerCount = new Ext.Toolbar.TextItem({
            text: SYNO.SDS.iCloudPhotoSync._T("album:cart_count", [Object.keys(self._cart).length])
        });

        var WinCls = (SYNO.SDS && SYNO.SDS.ModalWindow) ? SYNO.SDS.ModalWindow : Ext.Window;
        var win = new WinCls({
            title: SYNO.SDS.iCloudPhotoSync._T("album:cart_title"),
            icon: "/webman/3rdparty/iCloudPhotoSync/images/gallery_16.png",
            modal: true,
            width: Math.min(Ext.getBody().getWidth() - 100, 900),
            height: Math.min(Ext.getBody().getHeight() - 100, 700),
            resizable: true,
            maximizable: true,
            layout: "fit",
            items: [panel],
            fbar: {
                items: [footerCount, "->", clearBtn, exportBtn, closeBtn]
            },
            listeners: {
                afterrender: function () { bindClicks(); }
            }
        });
        win.show();
    },

    loadPhotos: function (albumName, libraryId) {
        var self = this;
        if (!this.currentAccountId) return;
        libraryId = libraryId || "personal";

        // Find album metadata for lazy-load strategy.
        var idx = this.albumStore.findBy(function (r) {
            return r.get("name") === albumName && r.get("library") === libraryId && r.get("type") !== "library_header";
        });
        var rec = idx >= 0 ? this.albumStore.getAt(idx) : null;
        var albumType = rec ? rec.get("type") : "user";
        var albumTotal = rec ? (rec.get("photo_count") || 0) : 0;

        var direction = this.photoSortCombo ? this.photoSortCombo.getValue() : "DESCENDING";

        // CloudKit DESCENDING starts rank 0 at newest and N-1 at oldest, so
        // paginating N-1→0 renders oldest-first. Emulate newest-first by
        // fetching ASC from near the end and reversing client-side.
        // Only use reverse-trick if we have a known positive total.
        var useReverseTrick = (direction === "DESCENDING" && albumTotal > 0);

        var initialOffset;
        var windowStart = 0, windowEnd = 0;
        if (useReverseTrick) {
            windowEnd = albumTotal;
            windowStart = Math.max(albumTotal - this.PAGE_SIZE, 0);
            initialOffset = windowStart;
        } else {
            initialOffset = 0;
        }

        this._photoViewGen++;
        this._photoView = {
            gen: this._photoViewGen,
            album: albumName,
            libraryId: libraryId,
            albumType: albumType,
            total: albumTotal,
            direction: direction,
            useReverseTrick: useReverseTrick,
            offset: initialOffset,
            windowStart: windowStart,
            windowEnd: windowEnd,
            windowBuffer: [],
            loaded: 0,
            loading: false,
            done: false,
            photos: []  // flat ordered list, used for preview prev/next
        };

        // Reset body to a fresh grid shell.
        this.photoPanel.body.update(
            '<div class="ics-thumb-grid" style="display:flex;flex-wrap:wrap;gap:6px;"></div>' +
            '<div class="ics-thumb-footer" style="text-align:center;padding:12px;color:#888;font-size:12px;">' +
              Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("album:loading_photos")) +
            '</div>'
        );

        // Bind scroll + dblclick listeners once per panel.
        if (!this._scrollBound) {
            this._scrollBound = true;
            var bodyEl = this.photoPanel.body.dom;
            bodyEl.addEventListener("scroll", function () {
                var v = self._photoView;
                if (!v || v.loading || v.done) return;
                var nearBottom = (bodyEl.scrollTop + bodyEl.clientHeight) >= (bodyEl.scrollHeight - 300);
                if (nearBottom) self._fetchNextPage();
            });
            bodyEl.addEventListener("dblclick", function (e) {
                var tile = e.target.closest ? e.target.closest(".ics-thumb-tile") : null;
                if (!tile) return;
                var idx = parseInt(tile.getAttribute("data-idx"), 10);
                if (!isNaN(idx)) self._openPreview(idx);
            });
            bodyEl.addEventListener("click", function (e) {
                var check = e.target.closest ? e.target.closest('.ics-thumb-check[data-action="select"]') : null;
                if (!check) return;
                var tile = check.closest(".ics-thumb-tile");
                if (!tile) return;
                e.stopPropagation();
                e.preventDefault();
                var idx = parseInt(tile.getAttribute("data-idx"), 10);
                if (!isNaN(idx)) self._toggleSelect(idx);
            });
        }

        this._fetchNextPage();
    },

    _openPreview: function (idx) {
        var self = this;
        var v = this._photoView;
        if (!v || !v.photos || !v.photos.length) return;
        if (idx < 0 || idx >= v.photos.length) return;

        var proxyBase = "/webman/3rdparty/iCloudPhotoSync/api.cgi?method=thumb&url=";
        var state = { idx: idx };

        var imgEl, captionEl, counterEl;

        var render = function () {
            var p = v.photos[state.idx];
            var url = p.medium_url || p.thumb_url || "";
            imgEl.src = url ? proxyBase + encodeURIComponent(url) : "";
            var dims = (p.width && p.height) ? p.width + "\u00d7" + p.height : "";
            var sizeKB = p.size ? Math.round(p.size / 1024) : 0;
            var sizeTxt = sizeKB > 1024 ? (sizeKB / 1024).toFixed(1) + " MB" : sizeKB + " KB";
            captionEl.innerHTML = Ext.util.Format.htmlEncode(p.filename || "") +
                (dims ? '  \u2014  ' + dims : '') +
                (sizeKB ? '  \u2014  ' + sizeTxt : '');
            counterEl.innerHTML = (state.idx + 1) + " / " + v.photos.length;
        };

        var go = function (delta) {
            var next = state.idx + delta;
            if (next < 0) next = v.photos.length - 1;
            if (next >= v.photos.length) next = 0;
            state.idx = next;
            render();
        };

        var saveLabel = Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("album:btn_save"));
        var html =
            '<div style="position:relative;display:flex;flex-direction:column;height:100%;background:#1e1e1e;">' +
              '<div style="flex:1;display:flex;align-items:center;justify-content:center;overflow:hidden;position:relative;">' +
                '<img class="ics-preview-img" style="max-width:100%;max-height:100%;object-fit:contain;display:block;" />' +
                '<div class="ics-preview-prev" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);width:44px;height:44px;border-radius:22px;background:rgba(0,0,0,0.5);color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:24px;user-select:none;">\u2039</div>' +
                '<div class="ics-preview-next" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);width:44px;height:44px;border-radius:22px;background:rgba(0,0,0,0.5);color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:24px;user-select:none;">\u203a</div>' +
                '<div class="ics-preview-counter" style="position:absolute;top:10px;right:14px;color:#fff;background:rgba(0,0,0,0.5);padding:4px 10px;border-radius:12px;font-size:12px;"></div>' +
              '</div>' +
              '<div style="display:flex;align-items:center;gap:10px;padding:8px 14px;background:#111;border-top:1px solid #000;">' +
                '<div class="ics-preview-caption" style="flex:1;color:#eee;font-size:12px;text-align:center;"></div>' +
                '<button type="button" class="ics-preview-save" style="background:#057feb;color:#fff;border:0;border-radius:4px;padding:6px 14px;font-size:12px;cursor:pointer;">\u2b73 ' + saveLabel + '</button>' +
              '</div>' +
            '</div>';

        var WinClass = (SYNO.SDS && SYNO.SDS.ModalWindow) ? SYNO.SDS.ModalWindow : Ext.Window;
        var win = new WinClass({
            title: SYNO.SDS.iCloudPhotoSync._T("album:preview_title"),
            modal: true,
            width: Math.min(Ext.getBody().getWidth() - 80, 1200),
            height: Math.min(Ext.getBody().getHeight() - 80, 900),
            layout: "fit",
            resizable: true,
            maximizable: true,
            closable: true,
            closeAction: "close",
            html: html,
            listeners: {
                afterrender: function (w) {
                    var dom = w.body.dom;
                    imgEl = dom.querySelector(".ics-preview-img");
                    captionEl = dom.querySelector(".ics-preview-caption");
                    counterEl = dom.querySelector(".ics-preview-counter");
                    dom.querySelector(".ics-preview-prev").addEventListener("click", function () { go(-1); });
                    dom.querySelector(".ics-preview-next").addEventListener("click", function () { go(1); });
                    var saveBtn = dom.querySelector(".ics-preview-save");
                    if (saveBtn) saveBtn.addEventListener("click", function () {
                        self._downloadPhoto(v.photos[state.idx]);
                    });
                    render();

                    var keyHandler = function (e) {
                        if (e.keyCode === 37) { go(-1); e.preventDefault(); }
                        else if (e.keyCode === 39) { go(1); e.preventDefault(); }
                        else if (e.keyCode === 27) { w.close(); }
                    };
                    document.addEventListener("keydown", keyHandler);
                    w.on("close", function () {
                        document.removeEventListener("keydown", keyHandler);
                    });
                }
            }
        });
        win.show();
    },

    _fetchNextPage: function () {
        var self = this;
        var v = this._photoView;
        if (!v || v.loading || v.done) return;
        v.loading = true;
        var gen = v.gen;

        // Decide the API direction. For the reverse-trick path we always
        // fetch ASC and flip client-side.
        var apiDirection = v.useReverseTrick ? "ASCENDING" : v.direction;
        var requestedLimit = this.PAGE_SIZE;

        // For reverse-trick, cap the limit to the remaining records in the
        // current window — we walk one [windowStart, windowEnd) window at a
        // time, retrying at the same offset if CloudKit returns a partial batch.
        if (v.useReverseTrick) {
            requestedLimit = Math.min(this.PAGE_SIZE, Math.max(v.windowEnd - v.offset, 3));
        }

        var reqParams = {
            action: "photos",
            account_id: this.currentAccountId,
            album: v.album,
            limit: requestedLimit,
            offset: v.offset,
            direction: apiDirection
        };
        if (v.libraryId && v.libraryId !== "personal") reqParams.library = v.libraryId;
        this.appWin.apiRequest("album", reqParams, function (success, data, errMsg) {
            v.loading = false;
            if (gen !== self._photoViewGen) return;
            var footer = self.photoPanel.body.dom.querySelector(".ics-thumb-footer");

            if (!success) {
                if (footer) footer.innerHTML = '<span style="color:#c00;">' +
                    Ext.util.Format.htmlEncode(errMsg || SYNO.SDS.iCloudPhotoSync._T("overview:status_error")) + '</span>';
                v.done = true;
                return;
            }

            var photos = (data && data.photos) || [];
            if (data && typeof data.total === "number" && data.total > 0) {
                if (v.total <= 0 || data.total > v.total) {
                    v.total = data.total;
                    if (v.useReverseTrick && v.windowEnd < v.total) {
                        v.windowEnd = v.total;
                    }
                }
            }

            var renderBatch = photos;  // photos to append to grid right now

            if (v.useReverseTrick) {
                // Accumulate into current window's buffer. Advance offset by
                // actual photos.length so partial batches are retried at the
                // correct offset instead of jumping past a gap.
                if (photos.length > 0) {
                    v.windowBuffer = v.windowBuffer.concat(photos);
                    v.offset += photos.length;
                }

                var windowFull = (v.offset >= v.windowEnd);
                var windowStalled = (photos.length === 0);

                if (windowFull || windowStalled) {
                    // Flush window to grid in reverse order (newest first).
                    renderBatch = v.windowBuffer.slice().reverse();
                    v.windowBuffer = [];

                    if (v.windowStart === 0) {
                        v.done = true;
                    } else {
                        v.windowEnd = v.windowStart;
                        v.windowStart = Math.max(v.windowStart - self.PAGE_SIZE, 0);
                        v.offset = v.windowStart;
                    }
                } else {
                    // Window not yet complete — don't render yet, fetch more at new offset.
                    renderBatch = [];
                }
            }

            // Append to grid.
            var grid = self.photoPanel.body.dom.querySelector(".ics-thumb-grid");
            if (grid && renderBatch.length > 0) {
                var px = self._thumbSizePx();
                var chunk = "";
                var startIdx = v.photos.length;
                for (var i = 0; i < renderBatch.length; i++) {
                    v.photos.push(renderBatch[i]);
                    chunk += self._renderThumb(renderBatch[i], px, startIdx + i);
                }
                grid.insertAdjacentHTML("beforeend", chunk);
            }
            v.loaded += renderBatch.length;

            // Advance offset / done-flag for non-reverse-trick paths.
            if (!v.useReverseTrick) {
                if (photos.length === 0) {
                    v.done = true;
                } else if (apiDirection === "ASCENDING") {
                    v.offset += photos.length;
                    if (v.total > 0 && v.offset >= v.total) v.done = true;
                } else { // DESCENDING (photostream/smart)
                    v.offset -= photos.length;
                    if (v.offset < 0) v.done = true;
                }
            }

            if (v.done && v.loaded === 0) {
                self.photoPanel.body.update(
                    '<div style="text-align: center; padding: 40px; color: #999;">' + SYNO.SDS.iCloudPhotoSync._T("album:empty_photos") + '</div>'
                );
                return;
            }

            if (footer) {
                if (v.done) {
                    footer.innerHTML = SYNO.SDS.iCloudPhotoSync._T("album:footer_photos_shown", [v.loaded.toLocaleString("de-DE")]);
                } else {
                    footer.innerHTML = SYNO.SDS.iCloudPhotoSync._T("album:footer_loading_count", [v.loaded.toLocaleString("de-DE"), v.total ? v.total.toLocaleString("de-DE") : "?"]);
                }
            }

            // If the content doesn't yet fill the panel, immediately pull
            // another page so lazy-load works even when the viewport is big.
            var bodyEl = self.photoPanel.body.dom;
            var midWindow = v.useReverseTrick && v.windowBuffer.length > 0;
            var nothingRendered = renderBatch.length === 0;
            var viewportEmpty = bodyEl.scrollHeight <= bodyEl.clientHeight + 50;
            if (!v.done && (midWindow || nothingRendered || viewportEmpty)) {
                // setTimeout so DOM reflow completes before deciding to refetch.
                setTimeout(function () {
                    if (!v.done && !v.loading) self._fetchNextPage();
                }, 0);
            }
        });
    }
});

// --- Sync Settings ---
Ext.define("SYNO.SDS.iCloudPhotoSync.SyncSettings", {
    extend: "Ext.Panel",

    constructor: function (config) {
        var self = this;
        this.currentAccountId = null;

        var folderOptions = [
            ["year_month_day", SYNO.SDS.iCloudPhotoSync._T("settings:folder_year_month_day")],
            ["year_month", SYNO.SDS.iCloudPhotoSync._T("settings:folder_year_month")],
            ["year", SYNO.SDS.iCloudPhotoSync._T("settings:folder_year")],
            ["flat", SYNO.SDS.iCloudPhotoSync._T("settings:folder_flat")]
        ];

        // Target directory — text field + browse button
        this.targetDirField = new SYNO.ux.TextFilter({
            fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_target_dir"),
            name: "target_dir",
            value: "",
            emptyText: SYNO.SDS.iCloudPhotoSync._T("settings:placeholder_target_dir"),
            flex: 1
        });

        this.browseBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("settings:btn_browse"),
            style: "margin-left: 8px;",
            handler: function () { self._openFolderChooser(); }
        });

        this.targetDirComposite = new Ext.Container({
            fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_target_dir"),
            layout: "hbox",
            anchor: "100%",
            items: [this.targetDirField, this.browseBtn]
        });

        this.saveBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("common:save"),
            btnStyle: "blue",
            handler: function () { self.saveConfig(); }
        });

        // Inline banner shown while a sync is running. Setting changes are
        // rejected by the backend during a sync, so we surface that here
        // instead of letting the user click Save and get a popup error.
        this.syncBlockedBanner = new Ext.BoxComponent({
            hidden: true,
            autoEl: {
                tag: "div",
                cls: "ics-sync-block-banner",
                style: "background:#fff3cd;border-left:4px solid #f0ad4e;padding:10px 14px;margin:0 0 12px 0;font-size:13px;color:#7a5d00;",
                html: SYNO.SDS.iCloudPhotoSync._T("settings:banner_sync_blocked")
            }
        });

        this.settingsForm = new SYNO.ux.FormPanel({
            border: false,
            autoScroll: true,
            bodyStyle: "padding: 20px; background: #fff;",
            labelWidth: 140,
            defaults: { anchor: "100%" },
            items: [
                this.syncBlockedBanner,
                { xtype: "syno_fieldset", title: SYNO.SDS.iCloudPhotoSync._T("settings:section_general"), items: [
                    this.targetDirComposite,
                    { xtype: "syno_combobox", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_sync_interval"), name: "sync_interval",
                      store: new Ext.data.ArrayStore({ fields: ["val", "label"], data: [
                          [0, SYNO.SDS.iCloudPhotoSync._T("settings:interval_manual")],
                          [1, SYNO.SDS.iCloudPhotoSync._T("settings:interval_hourly")],
                          [3, SYNO.SDS.iCloudPhotoSync._T("settings:interval_3h")],
                          [6, SYNO.SDS.iCloudPhotoSync._T("settings:interval_6h")],
                          [12, SYNO.SDS.iCloudPhotoSync._T("settings:interval_12h")],
                          [24, SYNO.SDS.iCloudPhotoSync._T("settings:interval_daily")]
                      ]}),
                      displayField: "label", valueField: "val",
                      mode: "local", triggerAction: "all", editable: false,
                      value: 6, anchor: "100%" },
                    { xtype: "syno_combobox", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_parallel_downloads"), name: "parallel_downloads",
                      store: new Ext.data.ArrayStore({ fields: ["val", "label"], data: [
                          [1, SYNO.SDS.iCloudPhotoSync._T("settings:parallel_1")],
                          [2, "2"],
                          [4, SYNO.SDS.iCloudPhotoSync._T("settings:parallel_4")],
                          [6, "6"],
                          [8, SYNO.SDS.iCloudPhotoSync._T("settings:parallel_8")]
                      ]}),
                      displayField: "label", valueField: "val",
                      mode: "local", triggerAction: "all", editable: false,
                      value: 4, anchor: "100%" }
                ]},
                { xtype: "syno_fieldset", title: SYNO.SDS.iCloudPhotoSync._T("settings:section_full_library"), items: [
                    { xtype: "syno_checkbox", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_full_library_sync"), name: "ps_enabled",
                      boxLabel: SYNO.SDS.iCloudPhotoSync._T("settings:checkbox_all_photos"), checked: true },
                    { xtype: "syno_combobox", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_folder_structure"), name: "ps_folder",
                      store: new Ext.data.ArrayStore({ fields: ["val", "label"], data: folderOptions }),
                      displayField: "label", valueField: "val",
                      mode: "local", triggerAction: "all", editable: false,
                      value: "year_month", anchor: "100%" }
                ]},
                { xtype: "syno_fieldset", title: SYNO.SDS.iCloudPhotoSync._T("settings:section_albums"), items: [
                    { xtype: "syno_checkbox", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_album_sync"), name: "album_enabled",
                      boxLabel: SYNO.SDS.iCloudPhotoSync._T("settings:checkbox_selected_albums"), checked: true },
                    { xtype: "syno_combobox", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_folder_structure"), name: "album_folder",
                      store: new Ext.data.ArrayStore({ fields: ["val", "label"], data: folderOptions }),
                      displayField: "label", valueField: "val",
                      mode: "local", triggerAction: "all", editable: false,
                      value: "flat", anchor: "100%" },
                    { xtype: "syno_checkbox", fieldLabel: " ", labelSeparator: "", name: "album_dedup",
                      boxLabel: SYNO.SDS.iCloudPhotoSync._T("settings:checkbox_dedup"), checked: true },
                    { xtype: "displayfield", hideLabel: true,
                      value: '<div style="font-size: 11px; color: #888; margin: 2px 0 0 145px;">' + SYNO.SDS.iCloudPhotoSync._T("settings:help_album_selection") + '</div>' }
                ]},
                { xtype: "syno_fieldset", title: SYNO.SDS.iCloudPhotoSync._T("settings:section_files"), items: [
                    { xtype: "syno_combobox", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_filenames"), name: "filenames",
                      store: new Ext.data.ArrayStore({ fields: ["val", "label"], data: [
                          ["original", SYNO.SDS.iCloudPhotoSync._T("settings:filename_original")],
                          ["date_based", SYNO.SDS.iCloudPhotoSync._T("settings:filename_date_based")]
                      ]}),
                      displayField: "label", valueField: "val",
                      mode: "local", triggerAction: "all", editable: false,
                      value: "original", anchor: "100%" },
                    { xtype: "syno_combobox", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_conflict"), name: "conflict",
                      store: new Ext.data.ArrayStore({ fields: ["val", "label"], data: [
                          ["skip", SYNO.SDS.iCloudPhotoSync._T("settings:conflict_skip")],
                          ["overwrite", SYNO.SDS.iCloudPhotoSync._T("settings:conflict_overwrite")],
                          ["rename", SYNO.SDS.iCloudPhotoSync._T("settings:conflict_rename")]
                      ]}),
                      displayField: "label", valueField: "val",
                      mode: "local", triggerAction: "all", editable: false,
                      value: "skip", anchor: "100%" },
                    { xtype: "syno_combobox", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_formats"), name: "formats",
                      store: new Ext.data.ArrayStore({ fields: ["val", "label"], data: [
                          ["original", SYNO.SDS.iCloudPhotoSync._T("settings:format_original")],
                          ["jpg_only", SYNO.SDS.iCloudPhotoSync._T("settings:format_jpg_only")],
                          ["both", SYNO.SDS.iCloudPhotoSync._T("settings:format_both")]
                      ]}),
                      displayField: "label", valueField: "val",
                      mode: "local", triggerAction: "all", editable: false,
                      value: "original", anchor: "100%",
                      listeners: {
                          select: function (combo, record) {
                              var slider = combo.ownerCt.find("name", "jpg_quality")[0];
                              if (slider) slider.setVisible(record.get("val") !== "original");
                          }
                      } },
                    { xtype: "syno_numberfield", fieldLabel: SYNO.SDS.iCloudPhotoSync._T("settings:label_jpg_quality"), name: "jpg_quality",
                      minValue: 10, maxValue: 100, value: 85, width: 80, hidden: true },
                    { xtype: "syno_checkbox", fieldLabel: " ", labelSeparator: "", name: "format_folders",
                      boxLabel: SYNO.SDS.iCloudPhotoSync._T("settings:checkbox_format_folders") }
                ]},
                { xtype: "syno_fieldset", title: SYNO.SDS.iCloudPhotoSync._T("settings:section_maintenance"), items: [
                    { xtype: "container", layout: "hbox", style: "margin: 4px 0;", items: [
                        new SYNO.ux.Button({
                            text: SYNO.SDS.iCloudPhotoSync._T("settings:btn_reset_defaults"),
                            handler: function () { self.resetDefaults(); }
                        }),
                        { xtype: "box", width: 10 },
                        new SYNO.ux.Button({
                            text: SYNO.SDS.iCloudPhotoSync._T("settings:btn_reset_database"),
                            handler: function () { self.resetDatabase(); }
                        })
                    ]}
                ]}
            ],
            fbar: { items: [this.saveBtn] }
        });

        var cfg = Ext.apply({
            title: SYNO.SDS.iCloudPhotoSync._T("tab:settings"),
            layout: "fit",
            border: false,
            items: [this.settingsForm]
        }, config);

        delete cfg.appWin;
        this.appWin = config.appWin;
        this.callParent([cfg]);
    },

    setSyncRunning: function (running) {
        if (this._syncRunning === running) return;
        this._syncRunning = running;
        if (this.syncBlockedBanner && this.syncBlockedBanner.setVisible) {
            this.syncBlockedBanner.setVisible(running);
        }
        if (this.saveBtn && this.saveBtn.setDisabled) {
            this.saveBtn.setDisabled(running);
        }
        if (this.browseBtn && this.browseBtn.setDisabled) {
            this.browseBtn.setDisabled(running);
        }
        // Disable every field in the form so the user can't tweak values
        // that would just be rejected on save.
        var form = this.settingsForm && this.settingsForm.getForm && this.settingsForm.getForm();
        if (form) {
            form.items.each(function (f) {
                if (f && f.setDisabled) f.setDisabled(running);
            });
        }
    },

    _openFolderChooser: function () {
        var self = this;
        try {
            var chooser = new SYNO.SDS.Utils.FileChooser.Chooser({
                owner: this.appWin,
                title: SYNO.SDS.iCloudPhotoSync._T("settings:chooser_title"),
                usage: { type: "chooseDir" },
                folderToolbar: true,
                listeners: {
                    choose: function (ch, path) {
                        // path object has .path property (e.g. "/photo/iCloud")
                        var p = (path && path.path) ? path.path : (typeof path === "string" ? path : "");
                        // Store as absolute path with volume prefix
                        if (p && p.charAt(0) === "/") {
                            self.targetDirField.setValue(p);
                        } else if (p) {
                            self.targetDirField.setValue("/" + p);
                        }
                        ch.close();
                        self._validateTargetPath(self.targetDirField.getValue());
                    }
                }
            });
            chooser.open();
        } catch (e) {
            // Fallback: if FileChooser is not available, let user type manually
            Ext.Msg.prompt(SYNO.SDS.iCloudPhotoSync._T("settings:prompt_title"), SYNO.SDS.iCloudPhotoSync._T("settings:prompt_instruction"), function (btn, text) {
                if (btn === "ok" && text) {
                    self.targetDirField.setValue(text);
                }
            }, this, false, this.targetDirField.getValue());
        }
    },

    _getDsmUser: function () {
        try { var u = _S("user"); if (u) return u; } catch (e) {}
        try { var u2 = SYNO.SDS.UserSettings && SYNO.SDS.UserSettings.getUser && SYNO.SDS.UserSettings.getUser(); if (u2) return typeof u2 === "string" ? u2 : u2.username || u2.name || ""; } catch (e) {}
        return "";
    },

    _validateTargetPath: function (path) {
        if (!path) return;
        var self = this;
        this.appWin.apiRequest("config", {
            action: "validate_path",
            path: path,
            dsm_user: this._getDsmUser()
        }, function (success, data) {
            if (!success || !data) return;
            if (data.writable) return;

            var title = SYNO.SDS.iCloudPhotoSync._T("settings:path_not_writable_title");
            var msg;
            if (data.no_acl_fs) {
                msg = SYNO.SDS.iCloudPhotoSync._T("settings:path_not_writable_no_acl", [
                    Ext.util.Format.htmlEncode(path),
                    Ext.util.Format.htmlEncode(data.fstype || "?")
                ]);
            } else {
                msg = SYNO.SDS.iCloudPhotoSync._T("settings:path_not_writable_acl", [
                    Ext.util.Format.htmlEncode(path)
                ]);
            }
            SYNO.SDS.iCloudPhotoSync._showDialog({
                title: title,
                msg: msg,
                level: "error",
                width: 560,
                height: 320
            });
        });
    },

    _field: function (name) {
        return this.settingsForm.getForm().findField(name);
    },

    loadConfig: function (accountId) {
        var self = this;
        this.currentAccountId = accountId;
        this._loadSeq = (this._loadSeq || 0) + 1;
        var seq = this._loadSeq;

        this.settingsForm.getForm().reset();

        this.appWin.apiRequest("config", {
            action: "get",
            account_id: accountId
        }, function (success, data) {
            if (seq !== self._loadSeq) return;
            if (!success || !data) return;

            self.targetDirField.setValue(data.target_dir || "");
            var f = self._field.bind(self);
            if (f("sync_interval")) f("sync_interval").setValue(data.sync_interval_hours || 6);

            var fullLibrary = data.full_library || data.photostream;
            if (fullLibrary) {
                if (f("ps_enabled")) f("ps_enabled").setValue(fullLibrary.enabled !== false);
                if (f("ps_folder")) f("ps_folder").setValue(fullLibrary.folder_structure || "year_month");
            }
            if (data.albums) {
                if (f("album_enabled")) f("album_enabled").setValue(data.albums.enabled !== false);
                if (f("album_folder")) f("album_folder").setValue(data.albums.folder_structure || "flat");
                if (f("album_dedup")) f("album_dedup").setValue(data.albums.deduplicate_hardlinks !== false);
            }

            if (f("filenames")) f("filenames").setValue(data.filenames || "original");
            if (f("conflict")) f("conflict").setValue(data.conflict || "skip");
            if (f("formats")) f("formats").setValue(data.formats || "original");
            if (f("jpg_quality")) {
                f("jpg_quality").setValue(data.jpg_quality || 85);
                f("jpg_quality").setVisible((data.formats || "original") !== "original");
            }
            if (f("format_folders")) f("format_folders").setValue(!!data.format_folders);
            if (f("parallel_downloads")) f("parallel_downloads").setValue(data.parallel_downloads || 4);
        });
    },

    saveConfig: function () {
        if (!this.currentAccountId) return;
        var f = this._field.bind(this);

        var configData = {
            target_dir: this.targetDirField.getValue(),
            sync_interval_hours: parseInt(f("sync_interval") ? f("sync_interval").getValue() : 6, 10) || 6,
            full_library: {
                enabled: f("ps_enabled") ? f("ps_enabled").getValue() : true,
                folder_structure: f("ps_folder") ? f("ps_folder").getValue() : "year_month"
            },
            photostream: {
                enabled: false,
                folder_structure: f("ps_folder") ? f("ps_folder").getValue() : "year_month"
            },
            albums: {
                enabled: f("album_enabled") ? f("album_enabled").getValue() : true,
                folder_structure: f("album_folder") ? f("album_folder").getValue() : "flat",
                deduplicate_hardlinks: f("album_dedup") ? f("album_dedup").getValue() : true
            },
            filenames: f("filenames") ? f("filenames").getValue() : "original",
            conflict: f("conflict") ? f("conflict").getValue() : "skip",
            formats: f("formats") ? f("formats").getValue() : "original",
            jpg_quality: f("jpg_quality") ? parseInt(f("jpg_quality").getValue(), 10) : 85,
            format_folders: f("format_folders") ? f("format_folders").getValue() : false,
            parallel_downloads: parseInt(f("parallel_downloads") ? f("parallel_downloads").getValue() : 4, 10) || 4
        };

        var dsmUser = this._getDsmUser();

        var self = this;
        var accountId = this.currentAccountId;
        var sendConfig = function (targetAction) {
            var params = {
                action: "set",
                account_id: accountId,
                dsm_user: dsmUser,
                config: Ext.encode(configData)
            };
            if (targetAction) params.target_action = targetAction;

            self.appWin.apiRequest("config", params, function (success, data, errMsg, errObj) {
                if (!success) {
                    // Backend signals that target_dir changed and there's
                    // existing synced data. Ask the user what to do and retry.
                    if (errObj && errObj.target_dir_changed) {
                        var n = errObj.manifest_total || 0;
                        var oldDir = errObj.old_target_dir || "";
                        var newDir = errObj.new_target_dir || "";
                        var msg = SYNO.SDS.iCloudPhotoSync._T("settings:msg_target_dir_changed", [
                            Ext.util.Format.htmlEncode(oldDir),
                            Ext.util.Format.htmlEncode(newDir),
                            n.toLocaleString("de-DE")
                        ]);
                        SYNO.SDS.iCloudPhotoSync._showTargetMoveDialog(
                            SYNO.SDS.iCloudPhotoSync._T("settings:dialog_change_target_dir"), msg, function (choice) {
                                if (choice === "cancel") return;
                                if (choice === "move") {
                                    // Save first with target_action=move, then launch move_runner
                                    sendConfig("move");
                                    self.appWin.apiRequest("move", {
                                        action: "start",
                                        account_id: accountId,
                                        old_dir: oldDir,
                                        new_dir: newDir
                                    }, function (ok, d, em) {
                                        if (!ok) {
                                            SYNO.SDS.iCloudPhotoSync._showMsg(
                                                SYNO.SDS.iCloudPhotoSync._T("overview:status_error"), em || SYNO.SDS.iCloudPhotoSync._T("settings:error_move_not_started"), "error");
                                        }
                                    }, true);
                                } else if (choice === "clear") {
                                    sendConfig("clear");
                                }
                            }
                        );
                        return;
                    }
                    SYNO.SDS.iCloudPhotoSync._showMsg(
                        SYNO.SDS.iCloudPhotoSync._T("overview:status_error"),
                        errMsg || SYNO.SDS.iCloudPhotoSync._T("settings:error_save_failed"),
                        "error"
                    );
                }
            }, true);
        };
        sendConfig("");
    },

    resetDefaults: function () {
        if (!this.currentAccountId) return;
        var self = this;
        var accountId = this.currentAccountId;
        SYNO.SDS.iCloudPhotoSync._showDialog({
            title: SYNO.SDS.iCloudPhotoSync._T("settings:confirm_reset_defaults_title"),
            msg: SYNO.SDS.iCloudPhotoSync._T("settings:confirm_reset_defaults"),
            level: "question",
            buttons: [
                { text: SYNO.SDS.iCloudPhotoSync._T("common:cancel"), choice: "cancel" },
                { text: SYNO.SDS.iCloudPhotoSync._T("settings:btn_reset_defaults"), primary: true, choice: "ok" }
            ],
            onClick: function (choice) {
                if (choice !== "ok") return;
                self.appWin.apiRequest("config", {
                    action: "reset_defaults",
                    account_id: accountId
                }, function (success, data, errMsg) {
                    if (success) {
                        self.loadConfig(accountId);
                        SYNO.SDS.iCloudPhotoSync._showMsg(
                            SYNO.SDS.iCloudPhotoSync._T("settings:confirm_reset_defaults_title"),
                            SYNO.SDS.iCloudPhotoSync._T("settings:msg_reset_defaults_ok"), "info");
                    } else {
                        SYNO.SDS.iCloudPhotoSync._showMsg(
                            SYNO.SDS.iCloudPhotoSync._T("overview:status_error"),
                            errMsg || SYNO.SDS.iCloudPhotoSync._T("settings:msg_reset_failed"), "error");
                    }
                }, true);
            }
        });
    },

    resetDatabase: function () {
        if (!this.currentAccountId) return;
        var self = this;
        var accountId = this.currentAccountId;
        SYNO.SDS.iCloudPhotoSync._showDialog({
            title: SYNO.SDS.iCloudPhotoSync._T("settings:confirm_reset_database_title"),
            msg: SYNO.SDS.iCloudPhotoSync._T("settings:confirm_reset_database"),
            level: "question",
            buttons: [
                { text: SYNO.SDS.iCloudPhotoSync._T("common:cancel"), choice: "cancel" },
                { text: SYNO.SDS.iCloudPhotoSync._T("settings:btn_reset_database"), primary: true, choice: "ok" }
            ],
            onClick: function (choice) {
                if (choice !== "ok") return;
                self.appWin.apiRequest("config", {
                    action: "reset_database",
                    account_id: accountId
                }, function (success, data, errMsg) {
                    if (success) {
                        SYNO.SDS.iCloudPhotoSync._showMsg(
                            SYNO.SDS.iCloudPhotoSync._T("settings:confirm_reset_database_title"),
                            SYNO.SDS.iCloudPhotoSync._T("settings:msg_reset_database_ok"), "info");
                    } else {
                        SYNO.SDS.iCloudPhotoSync._showMsg(
                            SYNO.SDS.iCloudPhotoSync._T("overview:status_error"),
                            errMsg || SYNO.SDS.iCloudPhotoSync._T("settings:msg_reset_failed"), "error");
                    }
                }, true);
            }
        });
    }
});

// --- Log Viewer (Placeholder) ---
Ext.define("SYNO.SDS.iCloudPhotoSync.LogViewer", {
    extend: "Ext.Panel",

    constructor: function (config) {
        var self = this;
        var pageSize = 50;

        this.logStore = new Ext.data.JsonStore({
            url: "/webman/3rdparty/iCloudPhotoSync/api.cgi",
            baseParams: { method: "log", action: "list", level: "INFO" },
            root: "data",
            totalProperty: "total",
            fields: ["level", "timestamp", "message"],
            autoLoad: false
        });

        this.pagingBar = new SYNO.ux.PagingToolbar({
            store: this.logStore,
            pageSize: pageSize,
            displayInfo: true,
            displayButtons: true,
            displayMsg: SYNO.SDS.iCloudPhotoSync._T("log:paging_display"),
            emptyMsg: SYNO.SDS.iCloudPhotoSync._T("log:empty_msg")
        });

        this.logGrid = new SYNO.ux.GridPanel({
            store: this.logStore,
            border: false,
            columns: [{
                header: SYNO.SDS.iCloudPhotoSync._T("log:col_level"),
                dataIndex: "level",
                width: 80,
                renderer: function (val) {
                    var color = "#333", label = val;
                    if (/error|critical|fatal/i.test(val)) { color = "#c00"; label = SYNO.SDS.iCloudPhotoSync._T("log:level_error"); }
                    else if (/warn/i.test(val)) { color = "#b8860b"; label = SYNO.SDS.iCloudPhotoSync._T("log:level_warning"); }
                    else if (/info/i.test(val)) { color = "#333"; label = SYNO.SDS.iCloudPhotoSync._T("log:level_info"); }
                    else if (/debug/i.test(val)) { color = "#999"; label = SYNO.SDS.iCloudPhotoSync._T("log:level_debug"); }
                    return '<span style="color:' + color + ';">' + Ext.util.Format.htmlEncode(label) + '</span>';
                }
            }, {
                header: SYNO.SDS.iCloudPhotoSync._T("log:col_timestamp"),
                dataIndex: "timestamp",
                width: 150
            }, {
                header: SYNO.SDS.iCloudPhotoSync._T("log:col_message"),
                dataIndex: "message",
                id: "log-message",
                renderer: function (val) {
                    return Ext.util.Format.htmlEncode(val);
                }
            }],
            autoExpandColumn: "log-message",
            viewConfig: { forceFit: false, emptyText: SYNO.SDS.iCloudPhotoSync._T("log:empty_entries") },
            bbar: this.pagingBar
        });

        this.levelCombo = new SYNO.ux.ComboBox({
            store: new Ext.data.ArrayStore({
                fields: ["val", "label"],
                data: [["ERROR", SYNO.SDS.iCloudPhotoSync._T("log:level_error")], ["WARNING", SYNO.SDS.iCloudPhotoSync._T("log:level_warning")], ["INFO", SYNO.SDS.iCloudPhotoSync._T("log:level_info")], ["DEBUG", SYNO.SDS.iCloudPhotoSync._T("log:level_debug")]]
            }),
            displayField: "label",
            valueField: "val",
            mode: "local",
            triggerAction: "all",
            editable: false,
            width: 120,
            value: "INFO",
            listeners: {
                select: function (combo, record) {
                    var lvl = record.get("val");
                    self.appWin.apiRequest("log", {
                        action: "set_level",
                        level: lvl
                    });
                    self.logStore.baseParams.level = lvl;
                    self.logStore.load({ params: { start: 0, limit: pageSize } });
                }
            }
        });

        this.retentionCombo = new SYNO.ux.ComboBox({
            store: new Ext.data.ArrayStore({
                fields: ["val", "label"],
                data: [
                    ["7", SYNO.SDS.iCloudPhotoSync._T("log:retention_7d")],
                    ["14", SYNO.SDS.iCloudPhotoSync._T("log:retention_14d")],
                    ["30", SYNO.SDS.iCloudPhotoSync._T("log:retention_30d")],
                    ["90", SYNO.SDS.iCloudPhotoSync._T("log:retention_90d")],
                    ["0", SYNO.SDS.iCloudPhotoSync._T("log:retention_all")]
                ]
            }),
            displayField: "label",
            valueField: "val",
            mode: "local",
            triggerAction: "all",
            editable: false,
            width: 100,
            value: "7",
            listeners: {
                select: function (combo, record) {
                    var days = record.get("val");
                    self.appWin.apiRequest("log", {
                        action: "set_retention",
                        days: days
                    }, function (success) {
                        if (success) {
                            self.logStore.load({ params: { start: 0, limit: pageSize } });
                        }
                    });
                }
            }
        });

        // Load current log level and retention from server
        (function () {
            self.appWin.apiRequest("log", { action: "get_level" }, function (success, data) {
                if (success && data && data.level) {
                    self.levelCombo.setValue(data.level);
                    self.logStore.baseParams.level = data.level;
                    if (self.logStore.getCount() > 0) {
                        self.logStore.load({ params: { start: 0, limit: pageSize } });
                    }
                }
            });
            self.appWin.apiRequest("log", { action: "get_retention" }, function (success, data) {
                if (success && data && data.retention_days !== undefined) {
                    self.retentionCombo.setValue(String(data.retention_days));
                }
            });
        }).defer(100);

        var cfg = Ext.apply({
            title: SYNO.SDS.iCloudPhotoSync._T("tab:log"),
            layout: "fit",
            border: false,
            items: [this.logGrid],
            tbar: [
                { xtype: "tbspacer", width: 4 },
                new SYNO.ux.Button({
                    text: SYNO.SDS.iCloudPhotoSync._T("log:btn_refresh"),
                    handler: function () { self.logStore.reload(); }
                }),
                new SYNO.ux.Button({
                    text: SYNO.SDS.iCloudPhotoSync._T("log:btn_clear"),
                    handler: function () {
                        self.appWin.getMsgBox().confirmDelete(SYNO.SDS.iCloudPhotoSync._T("log:confirm_title"), SYNO.SDS.iCloudPhotoSync._T("log:confirm_clear"), function (btn) {
                            if (btn === "yes") {
                                self.appWin.apiRequest("log", { action: "clear" }, function () {
                                    self.logStore.reload();
                                });
                            }
                        });
                    }
                }),
                new SYNO.ux.Button({
                    text: SYNO.SDS.iCloudPhotoSync._T("log:btn_export"),
                    tooltip: SYNO.SDS.iCloudPhotoSync._T("log:btn_export_tooltip"),
                    handler: function () {
                        // Navigate to the CGI endpoint directly — the browser handles
                        // the Content-Disposition: attachment header and prompts to
                        // save the ZIP without leaving the SPA.
                        var url = "/webman/3rdparty/iCloudPhotoSync/api.cgi?method=log_export";
                        window.location.href = url;
                    }
                }),
                "->",
                { xtype: "label", text: SYNO.SDS.iCloudPhotoSync._T("log:label_retention"), style: "font-size: 12px; color: #666; margin-right: 6px;" },
                this.retentionCombo,
                { xtype: "tbspacer", width: 12 },
                { xtype: "label", text: SYNO.SDS.iCloudPhotoSync._T("log:label_level"), style: "font-size: 12px; color: #666; margin-right: 6px;" },
                this.levelCombo,
                { xtype: "tbspacer", width: 4 }
            ]
        }, config);

        delete cfg.appWin;
        this.appWin = config.appWin;
        this.callParent([cfg]);

        this.on("activate", function () {
            if (self.logStore.getCount() === 0) {
                self.logStore.load({ params: { start: 0, limit: pageSize } });
            }
        });
    }
});

// --- About Tab ---
Ext.define("SYNO.SDS.iCloudPhotoSync.AboutTab", {
    extend: "Ext.Panel",

    constructor: function (config) {
        var self = this;

        var cfg = Ext.apply({
            title: SYNO.SDS.iCloudPhotoSync._T("tab:about"),
            autoScroll: true,
            bodyStyle: "background: #f7f8fa;",
            html: '<div style="display:flex;align-items:center;justify-content:center;height:100%;min-height:340px;">' +
                  '<div style="text-align:center;">' +
                  '<img src="/webman/3rdparty/iCloudPhotoSync/images/icon_64.png" style="width:64px;height:64px;margin-bottom:16px;" />' +
                  '<div style="font-size:18px;font-weight:700;color:#333;margin-bottom:4px;">iCloud Photo Sync</div>' +
                  '<div class="ics-about-version" style="font-size:13px;color:#888;margin-bottom:8px;"></div>' +
                  '<div class="ics-about-update" style="margin-bottom:24px;"></div>' +
                  '<div style="margin-bottom:24px;"><a href="https://github.com/Euphonique/iCloudPhotoSync" target="_blank" ' +
                  'style="color:#057feb;text-decoration:none;font-size:13px;">github.com/Euphonique/iCloudPhotoSync</a></div>' +
                  '<div style="font-size:13px;color:#888;">Made with ❤ by Pascal Pagel</div>' +
                  '<div><a href="https://www.pascalpagel.de" target="_blank" ' +
                  'style="color:#057feb;text-decoration:none;font-size:13px;">www.pascalpagel.de</a></div>' +
                  '</div></div>'
        }, config);

        delete cfg.appWin;
        this.appWin = config.appWin;
        this.callParent([cfg]);

        this.on("activate", function () {
            self._loadVersion();
            self._checkUpdate();
        });
    },

    _loadVersion: function () {
        var el = this.body && this.body.dom && this.body.dom.querySelector(".ics-about-version");
        if (!el || el.innerHTML) return;
        Ext.Ajax.request({
            url: "/webman/3rdparty/iCloudPhotoSync/api.cgi",
            params: { method: "status", action: "get" },
            success: function (resp) {
                try {
                    var d = Ext.decode(resp.responseText);
                    if (d && d.success && d.data && d.data.version) {
                        el.innerHTML = "v" + Ext.util.Format.htmlEncode(d.data.version);
                    }
                } catch (e) {}
            }
        });
    },

    _checkUpdate: function () {
        var self = this;
        var el = this.body && this.body.dom && this.body.dom.querySelector(".ics-about-update");
        if (!el) return;

        el.innerHTML = '<span style="font-size:12px;color:#999;">' +
            Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:checking_update")) + '</span>';

        Ext.Ajax.request({
            url: "/webman/3rdparty/iCloudPhotoSync/api.cgi",
            params: { method: "update", action: "check" },
            success: function (resp) {
                try {
                    var d = Ext.decode(resp.responseText);
                    if (d && d.success && d.data) {
                        self._renderUpdateInfo(el, d.data);
                    } else {
                        el.innerHTML = "";
                    }
                } catch (e) {
                    el.innerHTML = "";
                }
            },
            failure: function () {
                el.innerHTML = "";
            }
        });
    },

    _renderUpdateInfo: function (el, data) {
        var self = this;
        if (!data.update_available) {
            el.innerHTML = '<span style="font-size:12px;color:#5cb85c;">✓ ' +
                Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:up_to_date")) + '</span>';
            return;
        }

        var version = Ext.util.Format.htmlEncode(data.version);
        var notes = data.notes ? Ext.util.Format.htmlEncode(data.notes).replace(/\n/g, "<br>") : "";

        var html = '<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:12px 16px;margin:8px 0;max-width:360px;text-align:left;">' +
            '<div style="font-size:13px;font-weight:600;color:#856404;margin-bottom:6px;">' +
            Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:update_available")) + '</div>' +
            '<div style="font-size:12px;color:#856404;margin-bottom:8px;">v' + version + '</div>';

        if (notes) {
            html += '<details style="margin-bottom:10px;"><summary style="font-size:11px;color:#856404;cursor:pointer;">' +
                Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:release_notes")) + '</summary>' +
                '<div style="font-size:11px;color:#666;margin-top:6px;max-height:120px;overflow-y:auto;white-space:pre-wrap;">' +
                notes + '</div></details>';
        }

        html += '<button class="ics-update-btn" style="background:#057feb;color:#fff;border:none;border-radius:4px;' +
            'padding:6px 16px;font-size:12px;cursor:pointer;margin-right:8px;">' +
            Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:btn_install_update")) + '</button>';

        if (data.spk_url) {
            html += '<a href="' + Ext.util.Format.htmlEncode(data.spk_url) + '" target="_blank" ' +
                'style="font-size:11px;color:#057feb;text-decoration:none;">' +
                Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:btn_download_spk")) + '</a>';
        }

        html += '</div>';
        el.innerHTML = html;

        var btn = el.querySelector(".ics-update-btn");
        if (btn) {
            btn.addEventListener("click", function () {
                self._installUpdate(el, data);
            });
        }
    },

    _installUpdate: function (el, data) {
        var self = this;
        var btn = el.querySelector(".ics-update-btn");
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:installing"));
            btn.style.opacity = "0.6";
        }

        Ext.Ajax.request({
            url: "/webman/3rdparty/iCloudPhotoSync/api.cgi",
            params: { method: "update", action: "install" },
            timeout: 180000,
            success: function (resp) {
                try {
                    var d = Ext.decode(resp.responseText);
                    if (d && d.success) {
                        el.innerHTML = '<div style="background:#d4edda;border:1px solid #28a745;border-radius:6px;padding:12px 16px;max-width:360px;">' +
                            '<span style="font-size:13px;color:#155724;">✓ ' +
                            Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:update_installed")) + '</span></div>';
                    } else {
                        var msg = (d && d.error && d.error.message) || "Unknown error";
                        self._showInstallError(el, data, msg);
                    }
                } catch (e) {
                    self._showInstallError(el, data, e.message);
                }
            },
            failure: function () {
                self._showInstallError(el, data, SYNO.SDS.iCloudPhotoSync._T("common:connection_failed"));
            }
        });
    },

    _showInstallError: function (el, data, msg) {
        var html = '<div style="background:#f8d7da;border:1px solid #dc3545;border-radius:6px;padding:12px 16px;max-width:360px;text-align:left;">' +
            '<div style="font-size:12px;color:#721c24;margin-bottom:8px;">' +
            Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:install_failed")) + ': ' +
            Ext.util.Format.htmlEncode(msg) + '</div>';

        if (data.spk_url) {
            html += '<div style="font-size:11px;color:#721c24;">' +
                Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:install_manual_hint")) +
                ' <a href="' + Ext.util.Format.htmlEncode(data.spk_url) + '" target="_blank" ' +
                'style="color:#057feb;">' +
                Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("about:btn_download_spk")) + '</a></div>';
        }

        html += '</div>';
        el.innerHTML = html;
    }
});

// --- Status Bar (South Panel) ---
Ext.define("SYNO.SDS.iCloudPhotoSync.StatusBar", {
    extend: "Ext.Panel",

    constructor: function (config) {
        var cfg = Ext.apply({
            region: "south",
            height: 30,
            border: true,
            bodyStyle: "padding: 5px 12px; background: #f5f5f5; font-size: 12px; color: #666;",
            html: SYNO.SDS.iCloudPhotoSync._T("status:ready")
        }, config);

        delete cfg.appWin;
        this.appWin = config.appWin;
        this.callParent([cfg]);
    },

    updateStatus: function (data) {
        var text = SYNO.SDS.iCloudPhotoSync._T("status:ready");
        if (data.sync_status === "syncing") {
            text = SYNO.SDS.iCloudPhotoSync._T("status:syncing");
        } else if (data.sync_status === "idle") {
            text = SYNO.SDS.iCloudPhotoSync._T("status:ready_with_accounts", [data.accounts]);
            if (data.next_sync) {
                text += SYNO.SDS.iCloudPhotoSync._T("status:next_sync_suffix", [data.next_sync]);
            }
        } else if (data.sync_status === "error") {
            text = SYNO.SDS.iCloudPhotoSync._T("status:error");
        }
        this.body.update(text);
    }
});

// --- Account Wizard (Add Account Modal) ---
Ext.define("SYNO.SDS.iCloudPhotoSync.AccountWizard", {
    extend: "SYNO.SDS.ModalWindow",

    constructor: function (config) {
        var self = this;
        this.currentStep = "login"; // "login" or "2fa"
        this.pendingAccountId = null;
        this.pendingPhoneId = null;
        this.useSmsVerification = false;

        this.statusField = new Ext.form.DisplayField({
            hideLabel: true,
            value: "",
            style: "color: #c00; font-size: 12px; margin-top: 8px;"
        });

        var heroHtml =
            '<div style="text-align:center;padding:20px 0 8px;">' +
                '<img src="/webman/3rdparty/iCloudPhotoSync/images/appleicloud.png" style="width:160px;height:160px;display:inline-block;" />' +
                '<div style="font-size:20px;font-weight:600;color:#222;margin-top:10px;">' +
                    Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("wizard:instruction_login")) +
                '</div>' +
            '</div>';

        this.cancelBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("wizard:btn_cancel"),
            handler: function () { self.close(); }
        });

        this.submitBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("wizard:btn_login"),
            btnStyle: "blue",
            handler: function () { self.onSubmit(); }
        });

        var loginBtnRow = {
            xtype: "container",
            layout: "hbox",
            layoutConfig: { align: "middle" },
            items: [
                this.cancelBtn,
                { xtype: "box", flex: 1 },
                this.submitBtn
            ]
        };

        this.loginPanel = new SYNO.ux.FormPanel({
            border: false,
            bodyStyle: "padding: 0 20px 20px; background:#fff;",
            labelAlign: "top",
            defaults: { anchor: "100%" },
            items: [{
                xtype: "displayfield",
                hideLabel: true,
                value: heroHtml
            }, {
                xtype: "syno_textfield",
                hideLabel: true,
                name: "apple_id",
                allowBlank: false,
                emptyText: SYNO.SDS.iCloudPhotoSync._T("wizard:label_apple_id")
            }, {
                xtype: "syno_textfield",
                hideLabel: true,
                name: "password",
                inputType: "password",
                allowBlank: false,
                emptyText: SYNO.SDS.iCloudPhotoSync._T("wizard:label_password")
            },
            loginBtnRow,
            this.statusField
            ]
        });

        this.tfaStatusField = new Ext.form.DisplayField({
            hideLabel: true,
            value: "",
            style: "color: #c00; font-size: 12px; margin-top: 8px;"
        });

        var tfaHeroHtml =
            '<div style="text-align:center;padding:20px 0 8px;">' +
                '<img src="/webman/3rdparty/iCloudPhotoSync/images/appleicloud.png" style="width:160px;height:160px;display:inline-block;" />' +
                '<div style="font-size:20px;font-weight:600;color:#222;margin-top:10px;">' +
                    Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("wizard:title_2fa")) +
                '</div>' +
                '<div style="font-size:13px;color:#666;margin-top:8px;padding:0 20px;">' +
                    Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("wizard:instruction_2fa_init")) +
                '</div>' +
            '</div>';

        this.tfaInfoField = new Ext.form.DisplayField({
            hideLabel: true,
            value: tfaHeroHtml
        });
        this._tfaHeroHtml = tfaHeroHtml;

        this.smsLinkField = new Ext.form.DisplayField({
            hideLabel: true,
            value: ''
        });

        this.tfaCancelBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("wizard:btn_cancel"),
            handler: function () { self.close(); }
        });

        this.tfaSubmitBtn = new SYNO.ux.Button({
            text: SYNO.SDS.iCloudPhotoSync._T("wizard:btn_confirm"),
            btnStyle: "blue",
            handler: function () { self.onSubmit(); }
        });

        var tfaBtnRow = {
            xtype: "container",
            layout: "hbox",
            layoutConfig: { align: "middle" },
            items: [
                this.tfaCancelBtn,
                { xtype: "box", flex: 1 },
                this.tfaSubmitBtn
            ]
        };

        this.tfaPanel = new SYNO.ux.FormPanel({
            border: false,
            bodyStyle: "padding: 0 20px 20px; background:#fff;",
            labelAlign: "top",
            defaults: { anchor: "100%" },
            items: [
            this.tfaInfoField,
            {
                xtype: "syno_textfield",
                hideLabel: true,
                name: "code",
                allowBlank: false,
                maxLength: 6,
                emptyText: SYNO.SDS.iCloudPhotoSync._T("wizard:placeholder_2fa_code")
            },
            this.smsLinkField,
            tfaBtnRow,
            this.tfaStatusField
            ]
        });

        var cfg = Ext.apply({
            title: SYNO.SDS.iCloudPhotoSync._T("wizard:title_add_account"),
            width: 500,
            height: 520,
            resizable: false,
            layout: "card",
            activeItem: 0,
            items: [this.loginPanel, this.tfaPanel]
        }, config);

        delete cfg.appWin;
        delete cfg.accountList;
        delete cfg.reAuthAccountId;
        delete cfg.reAuthAppleId;
        this.appWin = config.appWin;
        this.accountList = config.accountList;
        this.reAuthAccountId = config.reAuthAccountId || null;
        this.reAuthAppleId = config.reAuthAppleId || null;

        // Re-auth mode: prefill Apple ID and lock the field
        if (this.reAuthAccountId) {
            cfg.title = SYNO.SDS.iCloudPhotoSync._T("wizard:title_reauth");
            this.pendingAccountId = this.reAuthAccountId;
        }

        this.callParent([cfg]);

        if (this.reAuthAccountId) {
            this.on("afterlayout", function () {
                var f = self.loginPanel.getForm().findField("apple_id");
                if (f && self.reAuthAppleId) {
                    f.setValue(self.reAuthAppleId);
                    f.setReadOnly(true);
                }
            }, this, { single: true });
        }

        // Always refresh the account list on close, so a cancelled new-account
        // (which is now in pending_2fa state on the server) shows up.
        this.on("close", function () {
            if (self.accountList && self.accountList.refreshAccounts) {
                self.accountList.refreshAccounts();
            }
            if (self.appWin && self.appWin.loadStatus) {
                self.appWin.loadStatus();
            }
        });

        // Bind SMS link click via DOM delegation
        this.on("afterrender", function () {
            var el = self.getEl();
            if (el) {
                el.on("click", function (e) {
                    if (e.getTarget("#ics-send-sms")) {
                        e.preventDefault();
                        self.sendSmsCode();
                    }
                });
            }
        });
    },

    setLoading: function (loading) {
        if (this.currentStep === "login") {
            if (this.submitBtn) this.submitBtn.setDisabled(loading);
        } else {
            if (this.tfaSubmitBtn) this.tfaSubmitBtn.setDisabled(loading);
        }
    },

    onSubmit: function () {
        if (this.currentStep === "login") {
            this.doLogin();
        } else {
            this.doVerify2FA();
        }
    },

    doLogin: function () {
        var self = this;
        var form = this.loginPanel.getForm();
        if (!form.isValid()) return;

        var values = form.getFieldValues();
        this.statusField.setValue('<span style="color: #666;">' + SYNO.SDS.iCloudPhotoSync._T("wizard:status_connecting") + '</span>');
        this.setLoading(true);

        var loginParams = {
            action: "login",
            apple_id: values.apple_id,
            password: values.password
        };
        if (self.reAuthAccountId) {
            loginParams.account_id = self.reAuthAccountId;
        }
        this.appWin.apiRequest("auth", loginParams, function (success, data, errMsg) {
            self.setLoading(false);

            if (!success) {
                var msg = errMsg || SYNO.SDS.iCloudPhotoSync._T("wizard:error_login_failed");
                // Clean up pyicloud internal error format
                msg = msg.replace(/\(.*PyiCloud.*\)/g, "").replace(/[\(\)']/g, "").trim();
                self.statusField.setValue('<span style="color: #c00;">' + Ext.util.Format.htmlEncode(msg) + '</span>');
                return;
            }

            self.pendingAccountId = data.account_id;
            self.pendingPhoneId = null;
            self.useSmsVerification = false;

            if (data.requires_2fa) {
                // Switch to 2FA panel
                self.currentStep = "2fa";
                self.getLayout().setActiveItem(1);
                self.setTitle(SYNO.SDS.iCloudPhotoSync._T("wizard:title_2fa"));

                self.tfaInfoField.setValue(
                    '<div style="text-align:center;padding:20px 0 8px;">' +
                        '<img src="/webman/3rdparty/iCloudPhotoSync/images/appleicloud.png" style="width:160px;height:160px;display:inline-block;" />' +
                        '<div style="font-size:20px;font-weight:600;color:#222;margin-top:10px;">' +
                            Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("wizard:title_2fa")) +
                        '</div>' +
                        '<div style="font-size:13px;color:#666;margin-top:8px;padding:0 20px;">' +
                            Ext.util.Format.htmlEncode(SYNO.SDS.iCloudPhotoSync._T("wizard:instruction_2fa_confirm")) +
                        '</div>' +
                    '</div>'
                );
                self.smsLinkField.setValue(
                    '<div style="margin-top: 8px; font-size: 12px; color: #666;">' +
                    '<a href="#" id="ics-send-sms" style="color: #0070c9;">' + SYNO.SDS.iCloudPhotoSync._T("wizard:link_send_sms") + '</a>' +
                    '</div>'
                );
                Ext.defer(function () {
                    var smsEl = Ext.get("ics-send-sms");
                    if (smsEl) {
                        smsEl.on("click", function (e) {
                            e.preventDefault();
                            self.sendSmsCode();
                        });
                    }
                }, 100);
            } else {
                // Login complete
                self.onAuthComplete();
            }
        });
    },

    sendSmsCode: function () {
        var self = this;
        if (!this.pendingAccountId) return;

        this.tfaStatusField.setValue('<span style="color: #666;">' + SYNO.SDS.iCloudPhotoSync._T("wizard:status_sending_sms") + '</span>');

        this.appWin.apiRequest("auth", {
            action: "send_sms",
            account_id: this.pendingAccountId
        }, function (success, data, errMsg) {
            if (success) {
                self.useSmsVerification = true;
                self.pendingPhoneId = data.phone_id || null;
                var msg = data.message || SYNO.SDS.iCloudPhotoSync._T("wizard:success_sms_sent");
                self.tfaStatusField.setValue('<span style="color: #080;">' + Ext.util.Format.htmlEncode(msg) + '</span>');
            } else {
                self.tfaStatusField.setValue('<span style="color: #c00;">' + Ext.util.Format.htmlEncode(errMsg || SYNO.SDS.iCloudPhotoSync._T("wizard:error_sms_failed")) + '</span>');
            }
        });
    },

    doVerify2FA: function () {
        var self = this;
        var form = this.tfaPanel.getForm();
        if (!form.isValid()) return;

        var values = form.getFieldValues();
        this.tfaStatusField.setValue('<span style="color: #666;">' + SYNO.SDS.iCloudPhotoSync._T("wizard:status_verifying") + '</span>');
        this.setLoading(true);

        var verifyParams = {
            action: "verify_2fa",
            account_id: this.pendingAccountId,
            code: values.code
        };
        // Only send phone_id if user explicitly requested SMS
        if (this.useSmsVerification && this.pendingPhoneId) {
            verifyParams.phone_id = this.pendingPhoneId;
        }
        this.appWin.apiRequest("auth", verifyParams, function (success, data, errMsg) {
            self.setLoading(false);

            if (!success) {
                var msg = errMsg || SYNO.SDS.iCloudPhotoSync._T("wizard:error_invalid_code");
                self.tfaStatusField.setValue('<span style="color: #c00;">' + Ext.util.Format.htmlEncode(msg) + '</span>');
                return;
            }

            self.onAuthComplete();
        });
    },

    onAuthComplete: function () {
        var self = this;
        var accountId = this.pendingAccountId || this.reAuthAccountId;
        this.appWin.apiRequest("account", { action: "list" }, function (success, data) {
            if (success && data && data.accounts) {
                self.accountList.accountStore.loadData(data.accounts);
                if (self.accountList.dataView && self.accountList.dataView.refresh) {
                    self.accountList.dataView.refresh();
                }
                var idx = self.accountList.accountStore.findExact("id", accountId);
                if (idx >= 0 && self.appWin.detailPanel) {
                    var rec = self.accountList.accountStore.getAt(idx);
                    self.accountList.selectedAccount = rec;
                    self.accountList.dataView.select(idx);
                    self.accountList.enableRemoveBtn(true);
                    self.appWin.detailPanel.loadAccount(rec.data);
                }
            }
            self.appWin.loadStatus();
        });
        this.close();
    }
});
