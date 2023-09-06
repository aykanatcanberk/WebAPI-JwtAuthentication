using JwtAuth.Core.Dtos;
using JwtAuth.Core.Entities;
using JwtAuth.Core.Interfaces;
using JwtAuth.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuth.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);
            if (user == null)
                return new AuthServiceResponseDto
                {
                    isSucceed = false,
                    Message = "Invalid Credentials."

                };

            var password = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!password)
                return new AuthServiceResponseDto
                {
                    isSucceed = false,
                    Message = "Invalid Credentials."

                };

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
            return new AuthServiceResponseDto
            {
                isSucceed = true,
                Message = token

            };

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

        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto permission)
        {
            var user = await _userManager.FindByNameAsync(permission.UserName);
            if (user == null)
                return new AuthServiceResponseDto
                {
                    isSucceed = false,
                    Message = "Invalid Username."

                };
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                if (role == "Admin")
                    return new AuthServiceResponseDto
                    {
                        isSucceed = true,
                        Message = "User was already admin."

                    };
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.Admin);
            return new AuthServiceResponseDto
            {
                isSucceed = true,
                Message = "User is admin now."

            };
        }

        public async Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto permission)
        {
            var user = await _userManager.FindByNameAsync(permission.UserName);
            if (user == null)
                return new AuthServiceResponseDto
                {
                    isSucceed = false,
                    Message = "Invalid username!"

                };
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                if (role == "Owner")
                    return new AuthServiceResponseDto
                    {
                        isSucceed = false,
                        Message = "User id already Owner."

                    };
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.Owner);
            return new AuthServiceResponseDto
            {
                isSucceed = true,
                Message = "User is owner now."

            };
            
        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isExist = await _userManager.FindByNameAsync(registerDto.UserName);
            if (isExist != null)
                return new AuthServiceResponseDto
                {
                    isSucceed = true,
                    Message = "Username already exists."

                };

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);
            if (!createUserResult.Succeeded)
            {
                var errorString = "User creation failed:";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += " " + error.Description;
                }
                return new AuthServiceResponseDto
                {
                    isSucceed = true,
                    Message = errorString

                };
            }

            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.User);
            return new AuthServiceResponseDto
            {
                isSucceed = true,
                Message = "User Created successfully."

            };
        }

        public async Task<AuthServiceResponseDto> SeedRolesAsync()
        {
            bool isOwnerRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.Owner);
            bool isAdminRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.Admin);
            bool isUserRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.User);

            if (isAdminRoleExist && isUserRoleExist && isOwnerRoleExist)
                return new AuthServiceResponseDto
                {
                    isSucceed = true,
                    Message = "Role seeding is successful."

                };

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.User));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.Admin));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.Owner));
            return new AuthServiceResponseDto
            {
                isSucceed = true,
                Message = "Role seeding is successful."

            };
        }
    }
}