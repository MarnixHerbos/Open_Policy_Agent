using Build.Security.AspNetCore.Middleware.Extensions;
using Build.Security.AspNetCore.Middleware.Request;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Read values from appsettings.json
var jwtAuthority = builder.Configuration["Jwt:Authority"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var corsOrigin = builder.Configuration["Cors:Origin"];
var opaBaseAddress = builder.Configuration["OPA:BaseAddress"];

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.Authority = jwtAuthority;
    options.Audience = jwtAudience;

});

//Add OPA integration
builder.Services.AddBuildAuthorization(options =>
{
    options.Enable = true;
    options.BaseAddress = opaBaseAddress;
    options.PolicyPath = "/barmanagement/allow";
    options.AllowOnFailure = false;
    options.Timeout = 5;

});

var app = builder.Build();

// Move CORS to run before the OPA-check middleware
app.UseCors(options => options
    .WithOrigins(corsOrigin)
    .AllowAnyMethod()
    .AllowAnyHeader());

// Simple middleware that queries OPA directly
app.Use(async (context, next) =>
{
    // Allow preflight/CORS to be handled and skip non-API requests
    if (string.Equals(context.Request.Method, "OPTIONS", StringComparison.OrdinalIgnoreCase) ||
        !context.Request.Path.StartsWithSegments("/api"))
    {
        await next();
        return;
    }

    context.Request.EnableBuffering();

    string body = null;
    if (context.Request.ContentLength > 0 &&
        context.Request.ContentType != null &&
        context.Request.ContentType.Contains("application/json"))
    {
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        body = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;
    }

    // extract bearer token
    var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
    string accessToken = null;
    if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        accessToken = authHeader.Substring("Bearer ".Length).Trim();
    }

    var opaInput = new
    {
        accessToken = accessToken,
        request = new
        {
            method = context.Request.Method,
            path = context.Request.Path.Value,
            body = string.IsNullOrWhiteSpace(body) ? null : JsonSerializer.Deserialize<object>(body)
        }
    };

    using var http = new HttpClient { BaseAddress = new Uri(opaBaseAddress) };
    var payload = new { input = opaInput };
    var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    HttpResponseMessage opaResp;
    try
    {
        opaResp = await http.PostAsync("/v1/data/barmanagement/allow", content);
    }
    catch (Exception ex)
    {
        Console.WriteLine("[DBG] OPA request failed: " + ex.Message);
        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("OPA unreachable");
        return;
    }

    var opaBody = await opaResp.Content.ReadAsStringAsync();
    bool allowed = false;
    try
    {
        using var doc = JsonDocument.Parse(opaBody);
        if (doc.RootElement.TryGetProperty("result", out var r) && r.ValueKind == JsonValueKind.True)
        {
            allowed = true;
        }
    }
    catch
    {
        Console.WriteLine("[DBG] Failed to parse OPA response: " + opaBody);
    }

    if (!allowed)
    {
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Forbidden");
        return;
    }

    await next();
});

// Configure the HTTP request pipeline.
app.UseAuthentication();
app.UseAuthorization();
// remove / keep app.UseBuildAuthorization() — if you keep it it will call OPA again
app.MapControllers();
app.Run();
