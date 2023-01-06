using ExoApi.Interfaces;
using ExoApi.Models;
using ExoApi.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.PortableExecutable;
using System.Security.Claims;

namespace ExoApi.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IUsuarioRepository _iUsuarioRepository;
        public LoginController(IUsuarioRepository iUsuarioRepository) 
        {
            _iUsuarioRepository= iUsuarioRepository;
        }
        [HttpPost]
        public IActionResult Login(LoginViewModel login)
        {
            try
            {
                Usuario usuarioBuscado = _iUsuarioRepository.Login(login.Email, login.Senha);
                if (usuarioBuscado == null)
                {
                    return Unauthorized(new { msg = "Email e/ou senha inválidos, tente novamente!" });
                }
                // Define os dados que serão fornecidos no token - Payload
                var minhasClaims = new[]
                {
                // armazena na Claim o e-mail do usuário autenticado
                new Claim(JwtRegisteredClaimNames.Email, usuarioBuscado.Email),

                // armazena na Claim o ID do usuário autenticado
                new Claim(JwtRegisteredClaimNames.Jti, usuarioBuscado.Id.ToString()),

                // armazena na Claim o tipo de usuário que foi autenticado
                new Claim(ClaimTypes.Role, usuarioBuscado.Tipo)
            };

                // chave de acesso ao token
                var chave = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("exoapi-chave-autenticacao"));

                // define as credenciais do token (Header)
                var credenciais = new SigningCredentials(chave, SecurityAlgorithms.HmacSha256);

                // gera o token
                var meuToken = new JwtSecurityToken(
                    issuer: "ExoApi",// emissor do token
                    audience: "ExoApi",// destinatário do token
                    claims: minhasClaims,// dados definidos nas claims
                    expires: DateTime.Now.AddMinutes(10),// tempo de expiração
                    signingCredentials: credenciais// credenciais do token
                    );
                // retorna o Ok com o token
                return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(meuToken) }
                    );
                
            }
            catch (Exception e)
            {
                return BadRequest(e);
            }
        }

    }
}
