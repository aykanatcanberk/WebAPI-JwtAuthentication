using JwtAuth.Core.Dtos;

namespace JwtAuth.Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDto> SeedRolesAsync();
        Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto);
        Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto);
        Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto permission);
        Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto permission);
    }
}
