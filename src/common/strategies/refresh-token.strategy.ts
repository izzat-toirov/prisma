import { ForbiddenException, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, JwtFromRequestFunction, Strategy } from 'passport-jwt';
import { JWTPayloadWithRefreshToken, JWTPload } from '../types';
import { Request } from 'express';


export const cookieExtractor: JwtFromRequestFunction = (req: Request) => {
    console.log(req.cookies);
    if(req && req.cookies){
        return req.cookies['refreshToken']
    }
    
}

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'refresh-jwt',
) {
  constructor() {
    super({
      jwtFromRequest: cookieExtractor,
      secretOrKey: process.env.REFRESH_TOKEN_KEY!,
      passReqToCallback: true,
    });
  }

  validate(req: Request, payload: JWTPload): JWTPayloadWithRefreshToken {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken){
        throw new ForbiddenException("Refresh token notogri");
    }
    return {...payload, refreshToken};
  }
}
