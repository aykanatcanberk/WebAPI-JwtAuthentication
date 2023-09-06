using JwtAuth.Core.Dtos;
using JwtAuth.Core.Entities;
using JwtAuth.Core.Interfaces;
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
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }
        [HttpPost("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedRole=await _authService.SeedRolesAsync();
            return Ok(seedRole);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            var register=await _authService.RegisterAsync(registerDto);
            if(register.isSucceed)
                return Ok(register);

            return BadRequest(register);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
           var login=await _authService.LoginAsync(loginDto);
           if(login.isSucceed)
                return Ok(login);

           return Unauthorized(login);
        }

        //make user to admin
        [HttpPost("make-admin")]
        public async Task<IActionResult> MakeAdmin(UpdatePermissionDto permission)
        {
            var adminResult= await _authService.MakeAdminAsync(permission);
            if(adminResult.isSucceed)
                return Ok(adminResult);

            return BadRequest(adminResult);
        }
        //make user to owner
        [HttpPost("make-owner")]
        public async Task<IActionResult> MakeOwner(UpdatePermissionDto permission)
        {
            var adminResult = await _authService.MakeOwnerAsync(permission);
            if (adminResult.isSucceed)
                return Ok(adminResult);

            return BadRequest(adminResult);
        }
    }

}