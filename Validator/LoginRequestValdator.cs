using AuthenticationAndAutorization.Model;
using FluentValidation;

namespace AuthenticationAndAutorization.Validator
{
    public class LoginRequestValdator: AbstractValidator<LoginRequest>
    {
        public LoginRequestValdator()
        {
            this.RuleFor(x => x.UserName)
            .NotEmpty()
            .WithMessage("UserName can't be empty")
            .MaximumLength(25)
            .WithMessage("UserName should't have more than 25 Character")
            .MinimumLength(3)
            .WithMessage("UserName should have atleast  3 Character");

            this.RuleFor(x => x.Password)
           .NotEmpty()
           .WithMessage("Password can't be empty")
           .MaximumLength(25)
           .WithMessage("Password should't have more than 25 Character")
           .MinimumLength(8)
           .WithMessage("Password should have atleast  8 Character");
        }
    }
}
