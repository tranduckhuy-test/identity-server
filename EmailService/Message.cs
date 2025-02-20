﻿using Microsoft.AspNetCore.Http;
using MimeKit;

namespace EmailService
{
    public class Message
    {
        public List<MailboxAddress> To { get; set; } = [];
        public string Subject { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public IFormFileCollection? Attachments { get; set; }


        public Message(IEnumerable<(string displayName, string email)> to, string subject, string content, IFormFileCollection? attachments)
        {
            To.AddRange(to.Select(x => new MailboxAddress(x.displayName, x.email)));
            Subject = subject;
            Content = content;

            if (attachments is not null)
            {
                Attachments = attachments;
            }
        }
    }
}
