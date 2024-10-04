using Build.Security.AspNetCore.Middleware.Extensions;
using Build.Security.AspNetCore.Middleware.Request;
using Microsoft.AspNetCore.Authentication.JwtBearer;

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

// Configure the HTTP request pipeline.
app.UseCors(options => options
    .WithOrigins(corsOrigin)
    .AllowAnyMethod()
    .AllowAnyHeader());

app.UseAuthentication();

// Add OPA integration
app.UseBuildAuthorization();

app.MapControllers();

app.Run();
