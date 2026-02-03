using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Helper to build TokenValidationParameters (reuse for issuing & validating)
TokenValidationParameters BuildValidationParameters(IConfiguration config)
{
    var keyString = config["Jwt:Key"] ?? string.Empty;
    // If key is base64, decode: Convert.FromBase64String(keyString)
    var keyBytes = Encoding.UTF8.GetBytes(keyString);
    return new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ClockSkew = TimeSpan.FromSeconds(30)
    };
}

// Add authentication services with events for diagnostics
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = BuildValidationParameters(builder.Configuration);

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // Optionally support tokens from query string for debugging: ?access_token=...
                // if (context.Request.Query.TryGetValue("access_token", out var token)) context.Token = token;
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
                var logger = loggerFactory.CreateLogger("JwtBearer");
                logger.LogError(context.Exception, "JWT authentication failed.");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
                var logger = loggerFactory.CreateLogger("JwtBearer");
                var sub = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                logger.LogInformation("Token validated for subject: {sub}", sub);

                // Example: enforce presence of a claim
                if (context.Principal?.HasClaim(c => c.Type == ClaimTypes.NameIdentifier) != true)
                {
                    logger.LogWarning("Token missing required claim: NameIdentifier");
                    context.Fail("Missing claim.");
                }

                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                // This runs when auth fails and a 401 is produced. Keep generic messages in production.
                var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
                var logger = loggerFactory.CreateLogger("JwtBearer");
                logger.LogWarning("JWT challenge: {error} - {errorDescription}", context.Error, context.ErrorDescription);
                return Task.CompletedTask;
            }
        };
    });

// Code specific to Angular
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalAngular", policy =>
        policy.WithOrigins("http://localhost:4200")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials());
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.MapType<DateOnly>(() => new OpenApiSchema { Type = "string", Format = "date" });
    c.AddSecurityDefinition("bearerAuth", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer' [space] and then your JWT token."
    });
    var bearerScheme = new OpenApiSecurityScheme
    {
        Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "bearerAuth" }
    };
    c.AddSecurityRequirement(new OpenApiSecurityRequirement { [ bearerScheme ] = new string[] { } });
});

var app = builder.Build();

// Code specific to Angular
app.UseCors("AllowLocalAngular");

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Debug endpoint (optional) to manually validate token payload
app.MapPost("/debug/validate-token", (string token, IConfiguration config) =>
{
    var tokenHandler = new JwtSecurityTokenHandler();
    try
    {
        var principal = tokenHandler.ValidateToken(token, BuildValidationParameters(config), out var validatedToken);
        return Results.Ok(new
        {
            Valid = true,
            Claims = principal.Claims.Select(c => new { c.Type, c.Value })
        });
    }
    catch (SecurityTokenException ex)
    {
        return Results.BadRequest(new { Valid = false, Error = ex.Message });
    }
});

app.MapPost("/token", (UserLogin login, IConfiguration config) =>
{
    if (login.Username == "testuser" && login.Password == "password123")
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "123"),
            new Claim(ClaimTypes.Name, login.Username),
            new Claim(ClaimTypes.Role, "User")
        };
        var keyBytes = Encoding.UTF8.GetBytes(config["Jwt:Key"] ?? string.Empty);
        var securityKey = new SymmetricSecurityKey(keyBytes);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: config["Jwt:Issuer"],
            audience: config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: credentials);
        var tokenHandler = new JwtSecurityTokenHandler();
        var accessToken = tokenHandler.WriteToken(token);
        return Results.Ok(new { AccessToken = accessToken });
    }
    return Results.Unauthorized();
});

app.MapGet("/secret", (ClaimsPrincipal user) => $"Hello {user.Identity?.Name}, welcome to the secret area!")
    .RequireAuthorization();

app.Run();

public record UserLogin(string Username, string Password);
