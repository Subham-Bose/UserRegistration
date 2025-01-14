﻿using UserAuthentication.Models;

namespace UserAuthentication.Services
{
    public interface IAuthService
    {
        public Task<User> Login(string email, string password);
        public Task<User> Register(User user);
    }
}
