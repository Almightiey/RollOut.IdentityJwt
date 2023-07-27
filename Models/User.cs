using System.ComponentModel.DataAnnotations;

namespace RollOut.IdentityJwt.Models
{
    public class User
    {
        public Guid UserId { get; set; }
        public Guid Id { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string PasswordSalt { get; set; } = string.Empty;
        public string Phone { get; set; } = string.Empty;
        public string Avatar { get; set; } = string.Empty;
        public bool IsSuperuser { get; set; }
        public bool IsStaff { get; set; }

        public string RefreshToken { get; set; } =string.Empty;
        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpires { get; set; }
    }
}
