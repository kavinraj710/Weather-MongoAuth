using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;
using Microsoft.JSInterop;
using BCrypt.Net;
using MongoAuth.Shared.Models;
using MongoAuth.Services;
using System.IdentityModel.Tokens.Jwt;
using MongoAuth.Components;
using System.ComponentModel.Design;
using Microsoft.AspNetCore.Components;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using static Supabase.Postgrest.Constants;


namespace MongoAuth.Services
{
    class AuthenticationProvider : AuthenticationStateProvider
    {
        public User? User { get; private set; } = new();

        private readonly IHttpContextAccessor _httpContextAccessor;
        //private readonly JwtTokenService _tokenService;
        //private readonly MongoDBServices _mongoDBServices;
        private readonly IConfiguration _configuration;
        private readonly Supabase.Client _supabaseClient;

        private AuthenticationState? _cachedAuthState = null;

        public AuthenticationProvider(
        IHttpContextAccessor httpContextAccessor,
        //JwtTokenService tokenService,
        IConfiguration configuration,
        Supabase.Client supabaseClient)
        {
            _httpContextAccessor = httpContextAccessor;
            //_tokenService = tokenService;
            _configuration = configuration;
            _supabaseClient = supabaseClient;
        }

        // This sets the Authentication State with User Roles
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            //await Task.Delay(1000);

            Console.WriteLine("From Get Auth State Function 1");

            if (_cachedAuthState != null)
            {
                Console.WriteLine($"Using Cached Auth State : {_cachedAuthState.User.Identity?.Name}");
                return _cachedAuthState;
            }

            Console.WriteLine("From Get Auth State Function 2");
            var authState = await FetchAuthState();
            _cachedAuthState = authState;

            Console.WriteLine($"Fetched New Auth State : {authState.User.Identity?.Name}");
            return authState;
        }

        public async Task SetUser(User? user)
        {
            Console.WriteLine("Hitting SetUser");
            Console.WriteLine("UserName: " + user?.name);
            if (user == null)
            {
                //User.Username = null;
                User = new User();
            }
            else
            {
                User = user;
            }
            _cachedAuthState = null;
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
        public async Task<AuthenticationState> FetchAuthState()
        {
            try
            {
                await Task.Delay(1000);
                // Retrieve tokens from cookies
                var accessToken = _httpContextAccessor.HttpContext.Request.Cookies["auth_token"];
                //var refreshToken = _httpContextAccessor.HttpContext.Request.Cookies["refresh_token"];
                Console.WriteLine("Access Token: " + accessToken);
                //Console.WriteLine("Refresh Token: " + refreshToken);

                if (!string.IsNullOrEmpty(accessToken))
                {
                    // Validate or decode the access token (if needed)
                    // You can skip this step if you trust the tokens from cookies
                    var sessionUser = await _supabaseClient.Auth.GetUser(accessToken);
                    if (sessionUser != null)
                    {
                        Console.WriteLine("User validated via access token: " + sessionUser.Email);

                        // Fetch additional user details from the database using the email
                        var response = await _supabaseClient.From<User>()
                            .Filter("email", Operator.Equals, sessionUser.Email)
                            .Get();

                        if (response.Models != null && response.Models.Any())
                        {
                            var user = response.Models.First();

                            // Create a ClaimsIdentity for the authenticated user
                            var identity = new ClaimsIdentity(new[]
                            {
                        new Claim(ClaimTypes.Email, user.email),
                        new Claim(ClaimTypes.Name, user.name),
                        new Claim(ClaimTypes.Role, user.role)
                    }, "SupabaseAuth");

                            Console.WriteLine($"Authenticated user: {user.name} with role {user.role}");

                            // Return the authenticated user's state
                            return new AuthenticationState(new ClaimsPrincipal(identity));
                        }
                        else
                        {
                            Console.WriteLine("No matching user found in the database.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error restoring auth state: {ex.Message}");
            }

            // Return unauthenticated state if no valid session or user is found
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));


            //var cookies = _httpContextAccessor.HttpContext.Request.Cookies;
            //var token = cookies.ContainsKey("auth_token") ? cookies["auth_token"] : null;
            //if (string.IsNullOrEmpty(token))
            //{
            //    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            //}

            //// Decode the JWT token and check validity.
            //var tokenHandler = new JwtSecurityTokenHandler();
            //JwtSecurityToken jwtToken;
            //var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

            //try
            //{
            //    var validationParameters = new TokenValidationParameters
            //    {
            //        ValidateIssuerSigningKey = true,
            //        IssuerSigningKey = new SymmetricSecurityKey(key),
            //        ValidateIssuer = true,
            //        ValidIssuer = _configuration["Jwt:Issuer"],
            //        ValidateAudience = true,
            //        ValidAudience = _configuration["Jwt:Audience"],
            //        ValidateLifetime = true,
            //        ClockSkew = TimeSpan.Zero
            //    };

            //    var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            //    var email = principal.FindFirst(ClaimTypes.Email)?.Value;
            //    Console.WriteLine("Email extracted from JWT: " + email);
            //    jwtToken = tokenHandler.ReadJwtToken(token);
            //    Console.WriteLine("Token : " + jwtToken);
            //    var user = await _mongoDBServices.GetUserByEmail(email);
            //    if (user != null)
            //    {
            //        User = user;
            //        return new AuthenticationState(principal);
            //    }
            //}
            //catch
            //{
            //    Console.WriteLine("Token Invalid");
            //}
            //return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            try { 
            var session = _supabaseClient.Auth.CurrentSession;
                Console.WriteLine("Session User ID: " + session?.User?.Id);
                Console.WriteLine("Session User Email: " + session?.User?.Email);

                if (session?.User == null)
            {
                Console.WriteLine("Supabase session invalid or expired.");
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

                // Fetch additional user data from the database
                var userId = (session.User.Id).ToString();
                Console.WriteLine(userId);
                var response = await _supabaseClient.From<User>()
                .Filter("id", Operator.Equals, userId) // Pass as Guid
                .Get();
                Console.WriteLine(response);
                if (response?.Model != null)
                {
                    Console.WriteLine("Fetched User Name: " + response.Model.name);
                }
                else
                {
                    Console.WriteLine("No user found with the given ID.");
                }

                var user = response?.Model;
                if (user != null)
                {
                    var identity = new ClaimsIdentity(new[]
                    {
                    new Claim(ClaimTypes.Email, user.email),
                    new Claim(ClaimTypes.Name, user.name), // Ensure this matches the expected claim type
                    new Claim(ClaimTypes.Role, user.role)
                    }, "SupabaseAuth");

                    Console.WriteLine("Claims set for user: " + user.name);

                    return new AuthenticationState(new ClaimsPrincipal(identity));
                }
            }
    catch (Exception ex)
    {
        Console.WriteLine($"Error fetching auth state: {ex.Message}");
    }

    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));


        }
    }
}