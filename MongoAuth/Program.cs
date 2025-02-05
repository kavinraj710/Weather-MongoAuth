using MongoAuth.Components;
using MudBlazor.Services;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using MongoAuth.Services;
using MongoDB.Driver;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using MongoAuth.Shared.Models;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.JSInterop;
using Supabase;
//using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents();

builder.Services.AddMudServices();
builder.Services.AddControllers();

var supabaseOptions = new Supabase.SupabaseOptions
{
    AutoRefreshToken = true, // Automatically refresh tokens when they expire
    //PersistSession = true    // Persist session across application restarts
};
var supabaseUrl = builder.Configuration["Supabase:Url"];
var supabaseKey = builder.Configuration["Supabase:Key"];
var supabaseClient = new Supabase.Client(supabaseUrl, supabaseKey, supabaseOptions);

builder.Services.AddSingleton(supabaseClient);

builder.Services.AddSingleton<SupabaseService>();
//builder.Services.AddSingleton<JwtTokenService>();

//builder.Services.AddSingleton<IJSRuntime>();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddSingleton<UserContext>();
builder.Services.AddAuthorizationCore();
builder.Services.AddSingleton<AuthenticationStateProvider, AuthenticationProvider>();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthenticationCore();

builder.Services.AddSignalR();

builder.Services.AddResponseCompression(opts =>
{
    opts.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(
        ["application/octet-stream"]);
});

builder.Services.AddHttpClient();


//var jwtKey = builder.Configuration["Jwt:Key"];
//var key = Encoding.ASCII.GetBytes(jwtKey);
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = false,
        //IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false,
        //ValidIssuer = builder.Configuration["Jwt:Issuer"],
        //ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateLifetime = true
        //IssuerSigningKey = new SymmetricSecurityKey(
        //        Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            if (string.IsNullOrEmpty(context.Token))
            {
                context.Token = context.Request.Cookies["auth_token"];
            }
            return Task.CompletedTask;
        }
    };

   // builder.Services.ConfigureApplicationCookie(options =>
   // {
   //     options.Cookie.HttpOnly = true;
   //     options.Cookie.SameSite = SameSiteMode.None; // Ensure the cookie works across sites.
   //     options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
   // });
   // //Special configuration for SignalR authentication

   //options.Events = new JwtBearerEvents
   //{
   //    OnMessageReceived = context =>
   //    {
   //        var accessToken = context.Request.Query["access_token"];
   //        var path = context.HttpContext.Request.Path;

   //        if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/mongoToDo"))
   //        {
   //            context.Token = accessToken;
   //        }
   //        return Task.CompletedTask;
   //    }
   //};
});

//builder.Services.AddDistributedMemoryCache();

// Enable sessions
//builder.Services.AddSession(options =>
//{
//    options.IdleTimeout = TimeSpan.FromMinutes(30);
//    options.Cookie.HttpOnly = true;
//    options.Cookie.IsEssential = true;
//});

//builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
//    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme,
//        options =>
//        {
//            options.LoginPath = new PathString("/login");
//        });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireLoggedIn", policy => policy.RequireAuthenticatedUser());
});

var app = builder.Build();

app.UseResponseCompression();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseRouting();
//app.UseSession();
app.UseAuthentication();
app.UseAuthorization();
app.UseStatusCodePages(context =>
{
    if (context.HttpContext.Response.StatusCode == 401)
    {
        context.HttpContext.Response.Redirect("/login");
    }
    return Task.CompletedTask;
});


app.UseAntiforgery();

//app.MapRazorComponents();
app.MapControllers();


//app.UseAuthentication();
//app.UseAuthorization();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode();
    //.AddAdditionalAssemblies(typeof(MongoAuth.Client._Imports).Assembly);


app.Run();
