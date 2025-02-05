using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using BCrypt.Net;
//using Isopoh.Cryptography.Argon2;
using MongoAuth.Shared.Models;
using MongoAuth.Services;

namespace MongoAuth.Components;

public class UserContext : ComponentBase
{
    [Inject] AuthenticationStateProvider Asp { get; set; } = default!;

    [Inject] IJSRuntime _jsRuntime { get; set; } = default!;


    [Inject] SupabaseService supabaseService { get; set; } = default!;

    //[Inject] JwtTokenService TokenService { get; set; } = default!;

    [Inject] NavigationManager Nav { get; set; } = default!;

    private AuthenticationProvider Auth { get; set; } = default!;

    public User User => Auth.User;

    protected override async void OnInitialized()
    {
        Console.WriteLine("From UserContext");
        Auth = (AuthenticationProvider)Asp;
        //await UserReAuthorize();
    }

    //public virtual Task OnAfterRenderContextAsync(bool firstRender)
    //{
    //    return Task.CompletedTask;
    //}


    // Cookie Writer
    public async Task WriteCookie(string cookieName, string cookieValue, int durationMinutes = 1)
    {
        await _jsRuntime.InvokeVoidAsync("CookieWriter.Write", cookieName, cookieValue, DateTime.Now.AddMinutes(durationMinutes));
    }

    // Cookie Reader
    public async Task<string> ReadCookie(string cookieName)
    {
        return await _jsRuntime.InvokeAsync<string>("CookieReader.Read", cookieName);
    }

    // Cookie Remover
    public async Task DeleteCookie(string cookieName)
    {
        await _jsRuntime.InvokeVoidAsync("CookieRemover.Delete", cookieName);
    }

    //public async Task<bool> Login()
    //{
    //    if (await UserReAuthorize()) { return true; }
    //    return false;
    //}

    public async Task<bool> LoginAsync(string email, string password)

    {
        var token = await supabaseService.LoginAsync(email, password);
        if (token != null)
        {
            await WriteCookie("auth_token", token, 60);
            return true;
        }
        return false;
        //    // Check if the input is empty
        //    if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password)) { return false; }

        //    var user = await supabaseService.GetUserByEmail(email);

        //    // check if the user is Valid
        //    //if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.Password)) { return false; }

        //    var token = TokenService.CreateSessionToken(user);
        //    Console.WriteLine("Token Created: " + token);
        //    await WriteCookie("auth_token", token, 30);
        //    Auth.SetUser(user);
        //    Console.WriteLine("user set");

        //    return true;
    }

    public async Task Logout(Guid userid)
    {
        Console.WriteLine("Logging out");
        await DeleteCookie("auth_token");
        // await Task.Delay(1000);
        await supabaseService.LogoutAsync();
        await Task.Delay(1000);
        Console.WriteLine("Logged out");
        // await _jsRuntime.InvokeVoidAsync("CookieRemover.Delete", "refreshtoken");
        await Auth.SetUser(null);
        await Task.Delay(1000);
        Nav.NavigateTo("/login", forceLoad: true);
    }

    //public async Task<bool> UserReAuthorize()
    //{
    //    string token = await ReadCookie("auth_token");
    //    if (string.IsNullOrEmpty(token)) { return false; }

    //    var user = await Database.GetUserByToken(token);
    //    if (user == null) { return false; }

    //    Auth.SetUser(user);
    //    return true;
    //}

    public void NavTo(string path, bool refresh = true)
    {
        Nav.NavigateTo(path, refresh);
    }

}