using AutoMapper;
using RollOut.IdentityJwt.Models;

public class AutoMapperProfile:Profile
{
    public AutoMapperProfile()
    {
        CreateMap<User, UserDto>();
        CreateMap<UserDto, User>();
    }
}
