using System.ComponentModel.DataAnnotations;

namespace DatingApp.API.Dtos
{
    public class UserForRegisterDto
    {
        [Required]
        public string Username { get; set; }

        [Required]
        [StringLength(8,MinimumLength = 4, ErrorMessage="Must be less than 4 and greater than 8!")]
        public string  Password { get; set; }
    }
}