using EmailService;
using IdentityServer.Entities;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityServer.Helpers
{
    public class MailMessageHelper
    {
        public static Message CreateMessage(User user, string token, string clientUri, string subject, string content)
        {

            var param = new Dictionary<string, string>
            {
                { "token", token },
                { "email", user.Email! }
            };

            var callbackUrl = QueryHelpers.AddQueryString(clientUri, param!);

            var message = new Message(
                [(user.UserName!, user.Email!)],
                subject,
                $"Please {content} by <a href='{callbackUrl}'>clicking here</a>.",
                null
            );

            return message;
        }
    }
}
