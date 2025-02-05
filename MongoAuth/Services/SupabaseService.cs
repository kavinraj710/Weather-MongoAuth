using System.Net.NetworkInformation;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using MongoAuth.Components;
using MongoAuth.Shared.Models;
using MongoDB.Driver.Core.Events;
using MudBlazor;
using Supabase.Interfaces;
using static Supabase.Postgrest.Constants;



namespace MongoAuth.Services
{
    public class SupabaseService
    {
        Supabase.Client _supabaseClient;
        IHttpContextAccessor _httpContextAccessor;
        UserContext _userContext;
        AuthenticationStateProvider Auth;
        private readonly ISnackbar _snackbar;
        public SupabaseService(Supabase.Client supabase, IHttpContextAccessor httpContextAccessor, AuthenticationStateProvider auth, UserContext userContext)
        { 
            _supabaseClient = supabase;
            _httpContextAccessor = httpContextAccessor;
            _userContext = userContext;
            Auth = auth;
            
        }
        public async Task<bool> RegisterUser(string email, string password, string username)
        {
            Console.WriteLine("Hitting Register User");
            var response = await _supabaseClient.Auth.SignUp(email, password);
            Console.WriteLine("Register User Response : " + response?.User);

            if (response?.User != null)
            {
                Console.WriteLine("If Success");
                // After successful registration, add additional user information to the DB
                var temp_id = Guid.Parse(response.User.Id);
                if (temp_id == null)
                {
                    Console.WriteLine("ID is null");
                }
                Console.WriteLine("ID is not null");
                var newUser = new MongoAuth.Shared.Models.User
                {
                    id = temp_id, // You can also use the ID from response.User.Id if available
                    email = email,
                    name = username,
                    role = "user", // Default role
                    created_at = DateTime.UtcNow 

                };

                Console.WriteLine("Inserting User: " + newUser);
                Console.WriteLine("Inserting User: " + newUser.id);
                Console.WriteLine("Inserting User: " + newUser.name);
                Console.WriteLine("Inserting User: " + newUser.email);
                Console.WriteLine("Inserting User: " + newUser.role);
                Console.WriteLine("Inserting User: " + newUser.created_at);

                var insertResponse = await _supabaseClient.From<MongoAuth.Shared.Models.User>().Insert(newUser);

                if (insertResponse != null)
                {
                    _snackbar.Add("User registered successfully!", Severity.Success);
                    Console.WriteLine("User Inserted Successfully");
                    return true;
                }
                else
                {
                    _snackbar.Add("Failed to save user to the database.", Severity.Error);
                    Console.WriteLine("Failed to Insert User");
                    return false;
                }
            }

            return false; 

        }
        public async Task<bool> SaveFavorite(string uname,string location, string description)
        {
            try
            {
                // Create a new instance of FavoriteCity
                var favorite = new MongoAuth.Shared.Models.FavoriteCity
                {
                    idd = Guid.NewGuid(), // Generate a new unique ID
                    description = description,
                    username = uname,
                    location=location
                };
                
                // Attempt to insert the favorite city into the Supabase table
                var insertResponse = await _supabaseClient.From<MongoAuth.Shared.Models.FavoriteCity>().Insert(favorite);
                
                // Check if the insertion was successful
                if (insertResponse != null && insertResponse.Models != null && insertResponse.Models.Any())
                {
                   
                    Console.WriteLine("Added to the Favorite Weather");
                    return true;
                }
                else
                {
                    
                    Console.WriteLine("Failed to insert favorite city. Response was null or empty.");
                    return false;
                }
            }
            catch (Exception ex)
            {
              
                Console.WriteLine($"Error while saving favorite city: {ex.Message}");
                return false;
            }
        }

        public async Task<string?> LoginAsync(string email, string password)
        {
            Console.WriteLine("Hitting LoginAsync");
            try
            {
                var response = await _supabaseClient.Auth.SignIn(email, password);

                if (response != null)
                {
                    // Store the token in a cookie
                    var accesstoken = response.AccessToken;
                    var refreshtoken = response.RefreshToken;

                    Console.WriteLine("Access Token: " + accesstoken);
                    Console.WriteLine("Refresh Token: " + refreshtoken);

                    //await Task.Delay(1000);
                    //SetCookie(accesstoken, refreshtoken);
                    var Response = await _supabaseClient.From<MongoAuth.Shared.Models.User>()
                    .Filter("email", Operator.Equals, email)
                    .Get();

                    // Check if any user was found
                    if (Response.Models != null && Response.Models.Any())
                    {
                        var user = Response.Models.First();
                        Console.WriteLine($"User found: {user.name} with email {user.email}");
                        ((AuthenticationProvider)Auth).SetUser(user);
                    }
                    return accesstoken;
                }
                return null;
            }
            catch (Exception ex) {
                Console.WriteLine("Error: " + ex.Message);
                return null;
            }
            }
        public async Task<List<FavoriteCity>> GetFavoriteCitiesAsync(string uname)
        {

            try
            {
                // Query the Supabase database for the user by email
                var response = await _supabaseClient.From<FavoriteCity>()
                    .Filter("username", Operator.Equals, uname)
                    .Get();

                // Check if the query returned any results
                if (response.Models != null && response.Models.Any())
                {
                    // Return the first matching user
                    return response.Models ?? new List<FavoriteCity>();
                }
                else
                {
                    Console.WriteLine($"No user found with email: {uname}");
                }
            }
            catch (Exception ex)
            {

            }

            // Return null if no user is found or an error occurs
            return null;
        }
        public async Task SetCookie(string accesstoken, string refreshtoken)
        {
            Console.WriteLine("Setting Cookies");
            var cookieOptions = new CookieOptions
            {
                //HttpOnly = true,
                //Secure = true,
                Expires = DateTime.UtcNow.AddMinutes(60)
            };
            //_httpContextAccessor.HttpContext.Response.Cookies.Append("auth_token", accesstoken, cookieOptions);
            //_httpContextAccessor.HttpContext.Response.Cookies.Append("refresh_token", refreshtoken, cookieOptions);
            _userContext.WriteCookie("auth_token", accesstoken, 60);
            //_userContext.WriteCookie("refresh_token", refreshtoken, 60);
            Console.WriteLine("Cookies Set");
            //await Task.CompletedTask;
        }

        public async Task LogoutAsync()
        {
            Console.WriteLine("Logging out user and clearing session...");
            await _supabaseClient.Auth.SignOut();

            // Clear cookies
            //_httpContextAccessor.HttpContext.Response.Cookies.Delete("auth_token");
            //_httpContextAccessor.HttpContext.Response.Cookies.Delete("refresh_token");
            //await Task.CompletedTask;
            //Console.WriteLine("User logged out and session cleared.");

        }

        public async Task<User?> GetUserByEmail(string email)
        {
            try
            {
                // Query the Supabase database for the user by email
                var response = await _supabaseClient.From<User>()
                    .Filter("email", Operator.Equals, email)
                    .Get();

                // Check if the query returned any results
                if (response.Models != null && response.Models.Any())
                {
                    // Return the first matching user
                    return response.Models.First();
                }
                else
                {
                    Console.WriteLine($"No user found with email: {email}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching user by email: {ex.Message}");
            }

            // Return null if no user is found or an error occurs
            return null;
        }

    }
}
