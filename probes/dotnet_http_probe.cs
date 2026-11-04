// Built offline into a temporary directory; no project or trust-store changes.
using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

class Diagnostic {
    static async Task Main(string[] args) {
        string state = "unknown", detail = "";
        try {
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseDefaultCredentials = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(double.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture)) };
            using var response = await client.GetAsync(args[0], HttpCompletionOption.ResponseHeadersRead);
            state = "accepted"; detail = "HTTP " + (int)response.StatusCode;
        } catch (Exception error) {
            state = "error";
            for (Exception e = error; e != null && detail.Length < 2500; e = e.InnerException)
                detail += e.GetType().Name + ": " + e.Message + " | ";
        }
        Console.WriteLine("EMUDHRA_JSON:" + JsonSerializer.Serialize(new { state, detail }));
    }
}
