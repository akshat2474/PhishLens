import ApplicationServices
import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  private var channel: FlutterMethodChannel?
  private weak var mainWindow: NSWindow?
  private var statusItem: NSStatusItem?
  private var hudPanel: NSPanel?
  private var hudDismissWorkItem: DispatchWorkItem?
  private var hudTitleField: NSTextField?
  private var hudSubField: NSTextField?
  private var hudDotView: NSView?

  private var lastChangeCount: Int = NSPasteboard.general.changeCount
  private var lastScannedUrl: String = ""
  private var pendingUrl: (url: String, source: String)?
  private var watchClipboard: Bool = true

  private let projectRoot = "/Users/akshat/Desktop/Stuff/ML_Proj"
  private let pythonBin = "/Users/akshat/Desktop/Stuff/ML_Proj/.venv/bin/python"

  func attachFlutterEngine(controller: FlutterViewController, window: NSWindow) {
    self.mainWindow = window
    let methodChannel = FlutterMethodChannel(
      name: "com.phishlens/mac",
      binaryMessenger: controller.engine.binaryMessenger
    )
    self.channel = methodChannel

    methodChannel.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      switch call.method {
      case "ready":
        if let pending = self.pendingUrl {
          self.pendingUrl = nil
          self.sendInterceptedUrl(pending.url, source: pending.source, showWindow: false)
        }
        result(AXIsProcessTrusted())
      case "scanWithPython":
        guard let args = call.arguments as? [String: Any],
              let url = args["url"] as? String else {
          result(FlutterError(code: "BAD_ARGS", message: "Missing URL", details: nil))
          return
        }
        self.runPythonScanner(url: url, result: result)
      case "notifyScanComplete":
        if let args = call.arguments as? [String: Any] {
          let url = (args["url"] as? String) ?? ""
          let riskPct = (args["risk_pct"] as? Double) ?? 0.0
          let works = (args["works"] as? Bool) ?? false
          let statusText = (args["status_text"] as? String) ?? ""
          let showHud = (args["show_hud"] as? Bool) ?? true
          self.updateMenuBarAndHud(
            url: url,
            riskPct: riskPct,
            works: works,
            statusText: statusText,
            showHud: showHud
          )
        }
        result(true)
      case "openInBrowser":
        if let args = call.arguments as? [String: Any],
           let url = args["url"] as? String,
           let browser = args["browser"] as? String {
          self.openUrlInBrowser(url: url, browser: browser)
        }
        result(true)
      case "requestAccessibility":
        let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        let trusted = AXIsProcessTrustedWithOptions(opts)
        result(trusted)
      case "setClipboardWatch":
        if let args = call.arguments as? [String: Any],
           let enabled = args["enabled"] as? Bool {
          self.watchClipboard = enabled
        }
        result(self.watchClipboard)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }

  override func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.servicesProvider = self
    setupStatusItem()
    setupHudPanel()
    setupGlobalDoubleClickMonitor()
    setupPasteboardWatcher()
    super.applicationDidFinishLaunching(notification)
  }

  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return false
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    return true
  }

  override func application(_ application: NSApplication, open urls: [URL]) {
    guard let first = urls.first else { return }
    var target = first.absoluteString
    if target.hasPrefix("phishlens://") {
      if let comps = URLComponents(url: first, resolvingAgainstBaseURL: false),
         let qUrl = comps.queryItems?.first(where: { $0.name == "url" })?.value {
        target = qUrl
      } else {
        target = target.replacingOccurrences(of: "phishlens://", with: "https://")
      }
    }
    sendInterceptedUrl(target, source: "macOS Link Click", showWindow: false)
  }

  @objc func handleCheckLinkService(
    _ pboard: NSPasteboard,
    userData: String,
    error: AutoreleasingUnsafeMutablePointer<NSString>
  ) {
    if let str = pboard.string(forType: .string),
       let extracted = extractCandidateUrl(from: str) {
      sendInterceptedUrl(extracted, source: "macOS Service", showWindow: false)
    }
  }

  private func setupStatusItem() {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    item.button?.title = "◎ PhishLens"
    let menu = NSMenu()
    menu.addItem(NSMenuItem(title: "Open Scan Logs & Inspector", action: #selector(showMainWindow), keyEquivalent: "o"))
    menu.addItem(NSMenuItem(title: "Scan Clipboard Link Now", action: #selector(scanClipboardNow), keyEquivalent: "v"))
    menu.addItem(NSMenuItem.separator())
    menu.addItem(NSMenuItem(title: "Quit PhishLens", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    item.menu = menu
    self.statusItem = item
  }

  private func setupHudPanel() {
    let width: CGFloat = 340
    let height: CGFloat = 68
    let panel = NSPanel(
      contentRect: NSRect(x: 0, y: 0, width: width, height: height),
      styleMask: [.borderless, .nonactivatingPanel],
      backing: .buffered,
      defer: false
    )
    panel.level = .statusBar
    panel.isOpaque = false
    panel.backgroundColor = .clear
    panel.hasShadow = true
    panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]

    let container = ClickableHudView(frame: NSRect(x: 0, y: 0, width: width, height: height))
    container.wantsLayer = true
    container.layer?.backgroundColor = NSColor(calibratedRed: 0.09, green: 0.09, blue: 0.09, alpha: 0.96).cgColor
    container.layer?.cornerRadius = 12
    container.layer?.borderWidth = 1
    container.layer?.borderColor = NSColor(calibratedRed: 0.22, green: 0.22, blue: 0.22, alpha: 1.0).cgColor
    container.onClick = { [weak self] in
      self?.hudPanel?.orderOut(nil)
      self?.showMainWindow()
    }

    let dot = NSView(frame: NSRect(x: 16, y: 38, width: 10, height: 10))
    dot.wantsLayer = true
    dot.layer?.cornerRadius = 5
    dot.layer?.backgroundColor = NSColor.systemGreen.cgColor
    container.addSubview(dot)
    self.hudDotView = dot

    let title = NSTextField(labelWithString: "PhishLens")
    title.frame = NSRect(x: 34, y: 34, width: width - 48, height: 20)
    title.font = NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .semibold)
    title.textColor = .white
    title.lineBreakMode = .byTruncatingTail
    container.addSubview(title)
    self.hudTitleField = title

    let sub = NSTextField(labelWithString: "Click to view full scan logs")
    sub.frame = NSRect(x: 34, y: 14, width: width - 48, height: 16)
    sub.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
    sub.textColor = NSColor(calibratedWhite: 0.68, alpha: 1.0)
    sub.lineBreakMode = .byTruncatingMiddle
    container.addSubview(sub)
    self.hudSubField = sub

    panel.contentView = container
    self.hudPanel = panel
  }

  private func updateMenuBarAndHud(
    url: String,
    riskPct: Double,
    works: Bool,
    statusText: String,
    showHud: Bool
  ) {
    let badge: String
    let dotColor: NSColor
    let verdictWord: String
    if riskPct >= 70.0 {
      badge = "🔴"
      dotColor = NSColor(calibratedRed: 0.898, green: 0.282, blue: 0.302, alpha: 1.0)
      verdictWord = "Phishing risk"
    } else if riskPct >= 50.0 {
      badge = "🟡"
      dotColor = NSColor(calibratedRed: 0.886, green: 0.639, blue: 0.212, alpha: 1.0)
      verdictWord = "Suspicious"
    } else {
      badge = "🟢"
      dotColor = NSColor(calibratedRed: 0.188, green: 0.643, blue: 0.424, alpha: 1.0)
      verdictWord = "Safe link"
    }

    let onlineWord = works ? "Online" : "Offline"
    let pctStr = String(format: "%.1f%%", riskPct)
    self.statusItem?.button?.title = "\(badge) \(pctStr) · \(onlineWord)"

    guard showHud, let panel = self.hudPanel else { return }
    self.hudDotView?.layer?.backgroundColor = dotColor.cgColor
    self.hudTitleField?.stringValue = "\(pctStr) \(verdictWord)  ·  \(works ? statusText : "Unreachable")"
    self.hudSubField?.stringValue = "\(url)  (click for logs)"
    panel.contentView?.layer?.borderColor = dotColor.withAlphaComponent(0.65).cgColor

    if let screen = NSScreen.main ?? NSScreen.screens.first {
      let vis = screen.visibleFrame
      let x = vis.maxX - panel.frame.width - 18
      let y = vis.maxY - panel.frame.height - 14
      panel.setFrameOrigin(NSPoint(x: x, y: y))
    }

    panel.alphaValue = 0.0
    panel.orderFrontRegardless()
    NSAnimationContext.runAnimationGroup { ctx in
      ctx.duration = 0.16
      panel.animator().alphaValue = 1.0
    }

    hudDismissWorkItem?.cancel()
    let work = DispatchWorkItem { [weak self] in
      guard let panel = self?.hudPanel else { return }
      NSAnimationContext.runAnimationGroup({ ctx in
        ctx.duration = 0.25
        panel.animator().alphaValue = 0.0
      }, completionHandler: {
        panel.orderOut(nil)
      })
    }
    hudDismissWorkItem = work
    DispatchQueue.main.asyncAfter(deadline: .now() + 3.6, execute: work)
  }

  @objc private func showMainWindow() {
    NSApp.activate(ignoringOtherApps: true)
    mainWindow?.makeKeyAndOrderFront(nil)
  }

  @objc private func scanClipboardNow() {
    if let raw = NSPasteboard.general.string(forType: .string),
       let url = extractCandidateUrl(from: raw) {
      sendInterceptedUrl(url, source: "Menu Bar Scan", showWindow: false)
    } else {
      showMainWindow()
    }
  }

  private func setupGlobalDoubleClickMonitor() {
    NSEvent.addGlobalMonitorForEvents(matching: .leftMouseUp) { [weak self] event in
      guard let self = self, event.clickCount >= 2 else { return }
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.14) {
        if let selected = self.readAccessibilitySelectedText(),
           let url = self.extractCandidateUrl(from: selected) {
          self.sendInterceptedUrl(url, source: "Double-Click", showWindow: false)
        }
      }
    }
  }

  private func setupPasteboardWatcher() {
    Timer.scheduledTimer(withTimeInterval: 0.45, repeats: true) { [weak self] _ in
      guard let self = self, self.watchClipboard else { return }
      let pb = NSPasteboard.general
      guard pb.changeCount != self.lastChangeCount else { return }
      self.lastChangeCount = pb.changeCount
      guard let raw = pb.string(forType: .string),
            let url = self.extractCandidateUrl(from: raw),
            url != self.lastScannedUrl else { return }
      self.sendInterceptedUrl(url, source: "Copied Link", showWindow: false)
    }
  }

  private func readAccessibilitySelectedText() -> String? {
    guard AXIsProcessTrusted() else { return nil }
    let systemWide = AXUIElementCreateSystemWide()
    var focusedRef: CFTypeRef?
    let err = AXUIElementCopyAttributeValue(
      systemWide,
      kAXFocusedUIElementAttribute as CFString,
      &focusedRef
    )
    guard err == .success, let focused = focusedRef else { return nil }
    let element = focused as! AXUIElement
    var selectedRef: CFTypeRef?
    if AXUIElementCopyAttributeValue(
      element,
      kAXSelectedTextAttribute as CFString,
      &selectedRef
    ) == .success, let text = selectedRef as? String, !text.isEmpty {
      return text
    }
    return nil
  }

  private func extractCandidateUrl(from raw: String) -> String? {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count >= 4, trimmed.count <= 2048 else { return nil }
    let pattern = #"(?i)\b((?:https?://|www\.)[^\s<>\"']+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|edu|gov|io|co|app|dev|ly|gl|me|info|biz|ru|cn|tk|xyz|top|site|online|uk|in|au)(?:/[^\s<>\"']*)?)"#
    guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
    let range = NSRange(trimmed.startIndex..<trimmed.endIndex, in: trimmed)
    guard let match = regex.firstMatch(in: trimmed, options: [], range: range),
          let matchRange = Range(match.range(at: 1), in: trimmed) else {
      return nil
    }
    return String(trimmed[matchRange])
  }

  private func sendInterceptedUrl(_ url: String, source: String, showWindow: Bool) {
    lastScannedUrl = url
    statusItem?.button?.title = "◎ Scanning…"
    if showWindow {
      showMainWindow()
    }
    guard let channel = self.channel else {
      self.pendingUrl = (url: url, source: source)
      return
    }
    channel.invokeMethod(
      "onLinkIntercepted",
      arguments: ["url": url, "source": source, "show_hud": !showWindow]
    )
  }

  private func runPythonScanner(url: String, result: @escaping FlutterResult) {
    DispatchQueue.global(qos: .userInitiated).async {
      let proc = Process()
      proc.executableURL = URL(fileURLWithPath: self.pythonBin)
      proc.currentDirectoryURL = URL(fileURLWithPath: self.projectRoot)
      proc.arguments = ["-m", "src.mac_scanner_cli", url]
      var env = ProcessInfo.processInfo.environment
      env["PYTHONPATH"] = self.projectRoot
      proc.environment = env

      let outPipe = Pipe()
      let errPipe = Pipe()
      proc.standardOutput = outPipe
      proc.standardError = errPipe

      do {
        try proc.run()
        proc.waitUntilExit()
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        if proc.terminationStatus == 0,
           let jsonStr = String(data: data, encoding: .utf8),
           !jsonStr.isEmpty {
          DispatchQueue.main.async { result(jsonStr) }
        } else {
          let errStr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "Scanner error"
          DispatchQueue.main.async {
            result(FlutterError(code: "SCAN_ERR", message: errStr, details: nil))
          }
        }
      } catch {
        DispatchQueue.main.async {
          result(FlutterError(code: "EXEC_ERR", message: error.localizedDescription, details: nil))
        }
      }
    }
  }

  private func openUrlInBrowser(url: String, browser: String) {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    if browser == "Safari" || browser == "Google Chrome" {
      proc.arguments = ["-a", browser, url]
    } else {
      proc.arguments = [url]
    }
    try? proc.run()
  }
}

final class ClickableHudView: NSView {
  var onClick: (() -> Void)?
  override func mouseDown(with event: NSEvent) {
    onClick?()
  }
}
