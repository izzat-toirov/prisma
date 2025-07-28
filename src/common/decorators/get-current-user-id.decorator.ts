import {
  createParamDecorator,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { JWTPload } from '../types';

export const GetCurrentUserId = createParamDecorator(
  (_: undefined, context: ExecutionContext): number => {
    const request = context.switchToHttp().getRequest();
    const user = request.user as JWTPload;
    if (!user) {
      throw new ForbiddenException('Token notogri');
    }
    console.log('user', user);
    return user.id;
  },
);
