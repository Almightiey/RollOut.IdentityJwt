using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RollOut.IdentityJwt.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]/[action]")]
public class AuthController : ControllerBase
{
    private readonly IDbContext _dbContext;
    private readonly IMapper _mapper;
    private readonly IConfiguration _config;
    public AuthController(IDbContext dbContext, IMapper mapper, IConfiguration config)
    {
        _dbContext = dbContext;
        _mapper = mapper;
        _config = config;
    }

    [HttpGet, Authorize]
    public async Task<ActionResult<IEnumerable<User>>> GetAll(CancellationToken cancellationToken)
    {
        var users = await _dbContext.Users.Where(user => user != null).ToListAsync(cancellationToken);
        return Ok(users);
    }

    [HttpGet, Authorize]
    public ActionResult<string> GetMyName()
    {
        var username = User?.Identity?.Name;
        var roleClaims = User?.FindAll(ClaimTypes.Role);

        var roles = roleClaims?.Select(c=>c.Value).ToList();
        return Ok(new { username, roles });
    }

    [HttpPost]
    public async Task<ActionResult<User>> Registration(UserDto request, CancellationToken cancellationToken)
    {
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

        var user = _mapper.Map<User>(request);
        user.PasswordHash = passwordHash;

        await _dbContext.Users.AddAsync(user, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return Ok(user);
    }

    [HttpPost]
    public async Task<ActionResult<User>> Login(UserDto request, CancellationToken cancellationToken)
    {
        var user = await _dbContext.Users.FirstOrDefaultAsync(user => user.UserName == request.UserName);
        if (user == null)
            return BadRequest("User not found.");

        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            return BadRequest("Wrong Password.");

        string token = CreateToken(user);

        return Ok(token);
    }



    private string CreateToken(User user)
    {
        List<Claim> claims = new List<Claim> {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Role,"Admin"),
            new Claim(ClaimTypes.Role,"User"),
        };

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(
                _config.GetSection("AppSettings:Token").Value!));  //TODO: Azure Key Vault

        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1), //TODO: edit expires
                signingCredentials: cred
            );


        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        return "bearer " + jwt;
    }
}
