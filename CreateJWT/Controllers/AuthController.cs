using CreateJWT.Data;
using CreateJWT.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CreateJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _dbContext;

        public AuthController(IConfiguration configuration, ApplicationDbContext dbContext)
        {
            _configuration = configuration;
            _dbContext = dbContext;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserDto request)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            if (_dbContext != null)
            {
                var existingUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Username == request.Username);
                if (existingUser != null)
                {
                    return BadRequest("User already exists");
                }

                User user = new()
                {
                    Username = request.Username,
                    PasswordHash = passwordHash
                };

                _dbContext.Users.Add(user);
                await _dbContext.SaveChangesAsync();
                
                return Ok(user);
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Database context is not available.");
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserDto request)
        {
            if (_dbContext.Users == null)
            {
                return NotFound();
            }

            var user = await _dbContext.Users.FirstOrDefaultAsync(x => x.Username == request.Username);

            if (user == null)
            {
                return NotFound();
            }

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return BadRequest("Wrong password");
            }

            var token = CreateToken(user);
            HttpContext.Session.SetString("JwtToken", token);

            return Ok(token);
        }

        /*      
        [HttpGet]
        public ActionResult<String> GetCurrentSessionToken()
        {
            var token = HttpContext.Session.GetString("JwtToken");
            return Ok(token);
        }*/

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("JwtSettings:Token").Value!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

    }
}
