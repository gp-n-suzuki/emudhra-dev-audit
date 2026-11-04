import Foundation
import Security

// Native system trust, isolated cookies/credentials, no redirect or response body.
final class Probe: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    let done = DispatchSemaphore(value: 0)
    var result: [String: String]? = nil
    var trustFailure: [String: String]? = nil
    let testAnchor: SecCertificate?
    init(anchor: SecCertificate?) { testAnchor = anchor }
    func finish(_ value: [String: String]) {
        if result == nil { result = value; done.signal() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        // The optional anchor is only used by local fixtures; never installed in a keychain.
        if let anchor = testAnchor {
            SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
        }
        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            var state = "unknown"; var reason = "native certificate validation failed"
            if let error = error {
                let code = OSStatus(CFErrorGetCode(error))
                if (CFErrorGetDomain(error) as String) == NSOSStatusErrorDomain {
                    switch code {
                    case errSecCertificateRevoked: state = "error"; reason = "certificate revoked"
                    case errSecNotTrusted, errSecCreateChainFailed, errSecTrustSettingDeny:
                        state = "error"; reason = "certificate not trusted"
                    default: reason = "SecTrust code=\(code)"
                    }
                }
            }
            trustFailure = ["state": state, "detail": "macOS SecTrust: " + reason]
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        if let response = response as? HTTPURLResponse {
            finish(["state": "accepted", "detail": "macOS URLSession: HTTP \(response.statusCode)"])
        }
        completionHandler(.cancel)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finish(trustFailure ?? ["state": "unknown", "detail": "URLSession error code=\((error as NSError?)?.code ?? 0)"])
    }
}

let args = CommandLine.arguments
let seconds = Double(args[2]) ?? 8
var anchor: SecCertificate? = nil
if args.count > 3 {
    let pem = try String(contentsOfFile: args[3], encoding: .utf8)
    let base64 = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
    if let data = Data(base64Encoded: base64) { anchor = SecCertificateCreateWithData(nil, data as CFData) }
}
let probe = Probe(anchor: anchor)
let config = URLSessionConfiguration.ephemeral
config.httpCookieStorage = nil; config.urlCredentialStorage = nil
config.httpShouldSetCookies = false; config.timeoutIntervalForRequest = seconds
config.timeoutIntervalForResource = seconds
let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
let session = URLSession(configuration: config, delegate: probe, delegateQueue: queue)
var request = URLRequest(url: URL(string: args[1])!)
request.setValue("emudhra-dev-audit/2", forHTTPHeaderField: "User-Agent")
session.dataTask(with: request).resume()
let wait = probe.done.wait(timeout: .now() + seconds + 1)
let result = wait == .success ? probe.result! : ["state": "unknown", "detail": "URLSession timeout"]
session.invalidateAndCancel()
let json = try JSONSerialization.data(withJSONObject: result)
print("EMUDHRA_JSON:" + String(data: json, encoding: .utf8)!)
