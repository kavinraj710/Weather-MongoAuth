using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.JSInterop;
using MongoAuth.Shared.Models;

namespace MongoAuth.Services
{

    public class JwtTokenService
    {
        private readonly IConfiguration _configuration;

        private readonly IHttpContextAccessor _httpContextAccessor;

        public JwtTokenService(IConfiguration configuration, IHttpContextAccessor httpContextAccesor)
        {
            _configuration = configuration;
            _httpContextAccessor = httpContextAccesor;
            //_jsRuntime = jsRuntime;
        }

        public string CreateSessionToken(User user)
        {
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not found"));
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                new Claim(ClaimTypes.Name, user.name),
                new Claim(ClaimTypes.Email, user.email),
                new Claim(ClaimTypes.Role, user.role)
            }),
                Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpirationMinutes"])),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            //Console.WriteLine("Token Created: " + token);
            return tokenHandler.WriteToken(token);
        }

        public async Task SetAuthCookie(string token)
        {
            var options = new CookieOptions
            {
                HttpOnly = true, // Prevent JavaScript access
                Secure = true, // Use only over HTTPS
                SameSite = SameSiteMode.Strict // Restrict cookie to same-site requests
            };

            //if (60.HasValue)
            //{
                options.Expires = DateTimeOffset.UtcNow.AddMinutes(60);
            //}

            _httpContextAccessor.HttpContext.Response.Cookies.Append("authToken", token, options);
        }

        public async Task<string> GetAuthCookie()
        {
            var cookies = _httpContextAccessor.HttpContext.Request.Cookies;
            return cookies.ContainsKey("authToken") ? cookies["authToken"] : null;
        }

        public async Task RemoveAuthCookie()
        {
            if (_httpContextAccessor.HttpContext.Request.Cookies.ContainsKey("authToken"))
            {
                _httpContextAccessor.HttpContext.Response.Cookies.Delete("authToken");
            }
        }
    }
}