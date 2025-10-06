using System.ComponentModel.DataAnnotations;

namespace ApiFuncional.Models
{
    public class RegisterUserViewModel
    {
        [Required(ErrorMessage = "O {0} deve ser obrigatório")]
        [EmailAddress(ErrorMessage ="O {0} está no formato incorreto")]
        public string Email { get; set; }


        [Required(ErrorMessage ="O {0} deve ser obrigatório")]
        [StringLength(100, ErrorMessage ="O campo {0} precisa ter entre {2} e {1} caracteres",  MinimumLength = 6)]
        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "as senhas não conferem")]
        public string ConfirmPassword { get; set; }
    }

}
