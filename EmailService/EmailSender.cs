using MailKit.Net.Smtp;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace EmailService
{
    public class EmailSender : IEmailSender
    {
        private readonly EmailConfiguration _emailConfiguration;
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(EmailConfiguration emailConfiguration, ILogger<EmailSender> logger)
        {
            _emailConfiguration = emailConfiguration;
            _logger = logger;
        }

        public async Task SendEmailAsync(Message message)
        {
            var emailMessage = CreateEmailMessage(message);
            await Send(emailMessage);
        }

        private MimeMessage CreateEmailMessage(Message message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress(_emailConfiguration.UserName, _emailConfiguration.From));
            emailMessage.To.AddRange(message.To);
            emailMessage.Subject = message.Subject;

            var bodyBuilder = new BodyBuilder { HtmlBody = string.Format("<h2 style='color: blue;'>{0}</h2>", message.Content) };

            if (message.Attachments != null && message.Attachments.Any())
            {
                byte[] fileBytes;
                foreach (var attachment in message.Attachments)
                {
                    using (var ms = new MemoryStream())
                    {
                        attachment.CopyTo(ms);
                        fileBytes = ms.ToArray();
                    }
                    bodyBuilder.Attachments.Add(attachment.FileName, fileBytes, ContentType.Parse(attachment.ContentType));
                }
            }

            emailMessage.Body =  bodyBuilder.ToMessageBody();

            return emailMessage;
        }

        private async Task Send(MimeMessage mailMessage)
        {
            using var client = new SmtpClient();

            try
            {
                _logger.LogInformation("[EmailSender] Sending email...");
                _logger.LogInformation($"[EmailSender] From: {mailMessage.From}");
                _logger.LogInformation($"[EmailSender] Port: {_emailConfiguration.Port}");
                _logger.LogInformation($"[EmailSender] Password: {_emailConfiguration.Password}");
                _logger.LogInformation($"[EmailSender] SmtpServer: {_emailConfiguration.SmtpServer}");
                _logger.LogInformation($"[EmailSender] UserName: {_emailConfiguration.UserName}");


                await client.ConnectAsync(_emailConfiguration.SmtpServer, _emailConfiguration.Port, true);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                await client.AuthenticateAsync(_emailConfiguration.From, _emailConfiguration.Password);
                await client.SendAsync(mailMessage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while sending the email.");
            }
            finally
            {
                await client.DisconnectAsync(true);
                client.Dispose();
            }
        }
    }
}
