using AutoMapper;
using IdentityServer.Dtos.Requests;
using IdentityServer.Entities;

namespace IdentityServer.Mapper
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<UserRegistrationRequestDto, User>()
                .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.Email));
        }
    }
}
