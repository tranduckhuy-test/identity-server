using EmailService;
using IdentityServer.Dtos;
using IdentityServer.Dtos.Requests;
using IdentityServer.Dtos.Responses;
using IdentityServer.Entities;
using IdentityServer.Helpers;
using IdentityServer.Mapper;
using IdentityServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Security.Claims;

namespace IdentityServer.Controllers
{
    [Route("api/accounts")]
    public class AccountsController : BaseController
    {
        private readonly UserManager<User> _userManager;
        private readonly IAuthService _authService;
        private readonly IEmailSender _emailSender;

        public AccountsController(UserManager<User> userManager, IEmailSender emailSender, IAuthService authService)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _authService = authService;
        }

        [HttpPost("register")]
        [ProducesResponseType((int)HttpStatusCode.Created)]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.BadRequest)]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto request)
        {
            var badRequestResponse = CheckModelStateValidity();
            if (badRequestResponse != null)
            {
                return badRequestResponse;
            }

            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Message = "User already exists.",
                });
            }

            var newUser = AppMapper.Mapper.Map<User>(request);

            var result = await _userManager.CreateAsync(newUser, request.Password);

            if (!result.Succeeded)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Message = "User registration failed.",
                    Errors = result.Errors.Select(e => e.Description)
                });
            }

            await _userManager.AddToRoleAsync(newUser, AppConstants.Roles.User);

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

            var message = MailMessageHelper.CreateMessage(newUser, token, request.ClientUri, "Confirm Email", "confirm your email");

            _ = _emailSender.SendEmailAsync(message);

            return StatusCode((int)HttpStatusCode.Created);
        }

        [HttpPost("login")]
        [ProducesResponseType(typeof(UserLoginResponseDto), (int)HttpStatusCode.OK)]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.Unauthorized)]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto request)
        {
            var badRequestResponse = CheckModelStateValidity();
            if (badRequestResponse != null)
            {
                return badRequestResponse;
            }

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
            {
                return Unauthorized(new ApiResponse<UserLoginResponseDto>
                {
                    Message = "User does not exist.",
                });
            }

            if (!user.EmailConfirmed)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    Message = "Email not confirmed.",
                });
            }

            if (!await _userManager.CheckPasswordAsync(user, request.Password))
            {
                //await _userManager.AccessFailedAsync(user);

                //if (await _userManager.IsLockedOutAsync(user))
                //{
                //    return Unauthorized(new ApiResponse<object>
                //    {
                //        Message = "Your account is locked. Please try again later.",
                //    });
                //}

                return Unauthorized(new ApiResponse<object>
                {
                    Message = "Invalid credentials. Please try again.",
                });
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            var (accessToken, refreshToken) = await _authService.GenerateToken(user, userRoles, true);

            return Ok(new UserLoginResponseDto
            {
                UserId = user.Id,
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

        [HttpPost("forgot-password")]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.OK)]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.BadRequest)]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestDto request)
        {
            var badRequestResponse = CheckModelStateValidity();
            if (badRequestResponse != null)
            {
                return badRequestResponse;
            }
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Message = "User does not exist.",
                });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var message = MailMessageHelper.CreateMessage(user, token, request.ClientUri, "Reset Password", "reset your password");

            _ = _emailSender.SendEmailAsync(message);

            return Ok(new ApiResponse<object>
            {
                IsSuccess = true,
                Message = "Password reset link sent to your email."
            });
        }

        [HttpPost("reset-password")]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.OK)]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.BadRequest)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestDto request)
        {
            var badRequestResponse = CheckModelStateValidity();
            if (badRequestResponse != null)
            {
                return badRequestResponse;
            }
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Message = "User does not exist.",
                });
            }
            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.Password);
            if (!result.Succeeded)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Message = "Password reset failed.",
                    Errors = result.Errors.Select(e => e.Description)
                });
            }
            return Ok(new ApiResponse<object>
            {
                IsSuccess = true,
                Message = "Password reset successful."
            });
        }

        [HttpGet("confirm-email")]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.OK)]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.BadRequest)]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string email, [FromQuery] string token)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Message = "User does not exist.",
                });
            }
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Message = "Email confirmation failed.",
                    Errors = result.Errors.Select(e => e.Description)
                });
            }
            return Ok(new ApiResponse<object>
            {
                IsSuccess = true,
                Message = "Email confirmation successful."
            });
        }

        [HttpPost("resend-confirmation-email")]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.OK)]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.BadRequest)]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequestDto request)
        {
            var badRequestResponse = CheckModelStateValidity();
            if (badRequestResponse != null)
            {
                return badRequestResponse;
            }
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Message = "User does not exist.",
                });
            }
            if (user.EmailConfirmed)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Message = "Email already confirmed.",
                });
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var message = MailMessageHelper.CreateMessage(user, token, request.ClientUri, "Confirm Email", "confirm your email");
            _ = _emailSender.SendEmailAsync(message);
            return Ok(new ApiResponse<object>
            {
                IsSuccess = true,
                Message = "Confirmation email sent."
            });
        }

        [HttpPost("refresh-token")]
        [ProducesResponseType(typeof(RefreshTokenDto), (int)HttpStatusCode.OK)]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.Unauthorized)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto request)
        {
            var badRequestResponse = CheckModelStateValidity();
            if (badRequestResponse != null)
            {
                return badRequestResponse;
            }

            try
            {
                var (accessToken, refreshToken) = await _authService.RefreshToken(request);
                return Ok(new RefreshTokenDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                });
            }
            catch (SecurityTokenException ex)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    Message = ex.Message
                });
            }
        }

        [HttpDelete("logout")]
        [Authorize]
        [ProducesResponseType((int)HttpStatusCode.NoContent)]
        [ProducesResponseType(typeof(ApiResponse<object>), (int)HttpStatusCode.Unauthorized)]
        public async Task<IActionResult> Logout()
        {
            var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");

            var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            if (userId == null)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    Message = "User not found."
                });
            }

            await _authService.Logout(userId, token);

            return NoContent();
        }
    }
}
