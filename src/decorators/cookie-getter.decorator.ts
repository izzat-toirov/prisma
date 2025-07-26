import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CookieGetter = createParamDecorator(
  (cookieName: string, ctx: ExecutionContext): string | undefined => {
    const request = ctx.switchToHttp().getRequest();
    return request.cookies?.[cookieName];
  },
);
