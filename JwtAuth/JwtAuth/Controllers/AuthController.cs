using JwtAuth.Core.Dtos;
using JwtAuth.Core.Entities;
using JwtAuth.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            bool isOwnerRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.Owner);
            bool isAdminRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.Admin);
            bool isUserRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.User);

            if (isAdminRoleExist && isUserRoleExist && isOwnerRoleExist)
                return Ok("Role seeding already done.");

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.User));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.Admin));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.Owner));
            return Ok("Role Seeding Done Successfully.");
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            var isExist=await _userManager.FindByNameAsync(registerDto.UserName);
            if (isExist != null)
                return BadRequest("Username already exists.");

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName=registerDto.FirstName,
                LastName=registerDto.LastName,
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            var createUserResult=await _userManager.CreateAsync(newUser,registerDto.Password);
            if(!createUserResult.Succeeded) 
            {
                var errorString = "User creation failed:";
                foreach(var error in createUserResult.Errors)
                {
                    errorString += " " + error.Description;
                }
                return BadRequest(errorString);
            }

            await _userManager.AddToRoleAsync(newUser,StaticUserRoles.User);
            return Ok("User Created Sucessfully.");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);
            if (user == null)
                return Unauthorized("Invalid Credentials.");

            var password = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!password)
                return Unauthorized("Invalid Credentials.");

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
             new Claim(ClaimTypes.Name, user.UserName),
             new Claim(ClaimTypes.NameIdentifier, user.Id),
             new Claim("JWTID", Guid.NewGuid().ToString()),
             new Claim("FirstName",user.FirstName),
             new Claim("LastName",user.LastName)
            };

            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = GenerateToken(authClaims);
            return Ok(token);
        }
        private string GenerateToken(List<Claim> claims)
        {
            try
            {
                var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                    _configuration.GetSection("JWT:Secret").Value!));

                var tokenObject = new JwtSecurityToken(
                    //issuer: _configuration["JWT:ValidIssuer"],
                   // audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(3),
                    claims: claims,
                    signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );

                var token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

                return token;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        //make user to admin
        [HttpPost("make-admin")]
        public async Task<IActionResult> MakeAdmin(UpdatePermissionDto permission)
        {
            var user = await _userManager.FindByNameAsync(permission.UserName);
            if (user == null)
                return BadRequest("Invalid Username.");
            var userRoles = await _userManager.GetRolesAsync(user);     
            foreach (var role in userRoles)
            {
                if (role == "Admin")
                    return Ok("User was already admin");
            }

            await _userManager.AddToRoleAsync(user,StaticUserRoles.Admin);
            return Ok("User is admin now.");
        }
        //make user to owner
        [HttpPost("make-owner")]
        public async Task<IActionResult> MakeOwner(UpdatePermissionDto permission)
        {
            var user = await _userManager.FindByNameAsync(permission.UserName);
            if (user == null)
                return Unauthorized("Invalid Username.");
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                if (role == "Owner")
                    return Ok("User was already Owner");
            }
            await _userManager.AddToRoleAsync(user,StaticUserRoles.Owner);
            return Ok("User is owner now.");
        }
    }

}