using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<VaultContext>(options =>
    options.UseSqlite("Data Source=safevault.db"));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "SafeVaultIssuer",
        ValidAudience = "SafeVaultAudience",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SuperSecretKey12345!SuperSecretKey12345!"))
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User", "Admin"));
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<VaultContext>();
    db.Database.EnsureCreated();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", async (UserDto userDto, VaultContext db) =>
{
    if (string.IsNullOrWhiteSpace(userDto.Username) || string.IsNullOrWhiteSpace(userDto.Password))
        return Results.BadRequest("Invalid input");

    if (await db.Users.AnyAsync(u => u.Username == userDto.Username))
        return Results.Conflict("User already exists");

    var hashedPassword = BCrypt.Net.BCrypt.HashPassword(userDto.Password);
    
    // Simple logic: First user is Admin, others are Users (for testing purposes)
    var role = !await db.Users.AnyAsync() ? "Admin" : "User";

    var user = new User
    {
        Username = HtmlEncoder.Default.Encode(userDto.Username),
        PasswordHash = hashedPassword,
        Role = role
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();

    return Results.Ok(new { Message = "User registered", Role = role });
});

app.MapPost("/login", async (UserDto userDto, VaultContext db) =>
{
    var user = await db.Users.SingleOrDefaultAsync(u => u.Username == userDto.Username);
    
    if (user == null || !BCrypt.Net.BCrypt.Verify(userDto.Password, user.PasswordHash))
        return Results.Unauthorized();

    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes("SuperSecretKey12345!SuperSecretKey12345!");
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        Issuer = "SafeVaultIssuer",
        Audience = "SafeVaultAudience",
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return Results.Ok(new { Token = tokenHandler.WriteToken(token) });
});

app.MapGet("/secrets", [Authorize(Policy = "UserOnly")] async (VaultContext db) =>
{
    return Results.Ok(await db.Secrets.ToListAsync());
});

app.MapPost("/secrets", [Authorize(Policy = "AdminOnly")] async (SecretDto secretDto, VaultContext db) =>
{
    if (string.IsNullOrWhiteSpace(secretDto.Content)) 
        return Results.BadRequest("Invalid content");

    var sanitizedContent = HtmlEncoder.Default.Encode(secretDto.Content);

    var secret = new Secret { Content = sanitizedContent };
    db.Secrets.Add(secret);
    await db.SaveChangesAsync();

    return Results.Created($"/secrets/{secret.Id}", secret);
});

app.Run();

public class VaultContext : DbContext
{
    public VaultContext(DbContextOptions<VaultContext> options) : base(options) { }
    public DbSet<User> Users => Set<User>();
    public DbSet<Secret> Secrets => Set<Secret>();
}

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "User";
}

public class Secret
{
    public int Id { get; set; }
    public string Content { get; set; } = string.Empty;
}

public class UserDto
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class SecretDto
{
    public string Content { get; set; }
}