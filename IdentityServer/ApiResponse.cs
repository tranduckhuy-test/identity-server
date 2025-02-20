﻿using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace IdentityServer
{
    public class ApiResponse<T>
    {
        public bool IsSuccess { get; set; }
        public T? Data { get; set; }
        public string Message { get; set; } = string.Empty;
        public IEnumerable<string> Errors { get; set; } = [];
    }
}
