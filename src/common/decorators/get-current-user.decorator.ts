import {
  createParamDecorator,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { JWTPayloadWithRefreshToken, JWTPload } from '../types';

export const GetCurrentUser = createParamDecorator(
  (
    data: keyof JWTPayloadWithRefreshToken,
    context: ExecutionContext,
  ): number => {
    const request = context.switchToHttp().getRequest();
    const user = request.user as JWTPload;
    console.log(user);
    console.log(data);
    if (!user) {
      throw new ForbiddenException('Token notogri');
    }
    if (!data) {
      return data;
    }
    return user[data];
  },
);
