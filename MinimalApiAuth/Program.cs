using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MinimalAuth;
using MinimalAuth.Models;
using MinimalAuth.Repositories;
using MinimalAuth.Services;

var builder = WebApplication.CreateBuilder(args);

//configuracao do jwt
var key = Encoding.ASCII.GetBytes(Settings.Secret);

builder.Services.AddAuthentication(x => 
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x => 
{
    x.RequireHttpsMetadata = false;
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("manager"));
    options.AddPolicy("Employee", policy => policy.RequireRole("employee"));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

//end points
app.MapGet("/", () => "Hello World!");

app.MapPost("/login", (User model) => {
    var user = UserRepository.Get(model.Username, model.Password);

    if(user == null)
        return Results.NotFound(new {message = "Ïnvalid username or password"});

    var token = TokenService.GenerateToken(user);

    user.Password = "";

    return Results.Ok(new
    {
        user = user,
        token = token
    });
});



app.MapGet("/anonymous", () => Results.Ok(""))
.AllowAnonymous();


app.MapGet("/authenticated", (ClaimsPrincipal  user) =>
{
    return Results.Ok(new
    {
        message = $"Autenticado como {user.Identity.Name}"
       
    });
    
}).RequireAuthorization();



app.MapGet("/employee", (ClaimsPrincipal  user) =>
{
    return Results.Ok(new
    {
        message = $"Autenticado como {user.Identity.Name}"
       
    });
}).RequireAuthorization("Employee");



app.MapGet("/manager", (ClaimsPrincipal  user) =>
{
     return Results.Ok(new
    {
        message = $"Autenticado como {user.Identity.Name}"
       
    });
}).RequireAuthorization("Admin");


app.Run();
