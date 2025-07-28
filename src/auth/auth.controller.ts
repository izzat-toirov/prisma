import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, SignInUserDto } from '../users/dto';
import { Response } from 'express';
import { CookieGetter } from '../common/decorators/cookie-getter.decorator';
import { ResponseFields } from '../common/types';
import { GetCurrentUser, GetCurrentUserId } from '../common/decorators';
import { RefreshTokenGuard } from '../common/guards';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(201)
  @Post('signUp')
  async signUp(@Body() createUserDto: CreateUserDto) {
    return this.authService.signUp(createUserDto);
  }

  @HttpCode(200)
  @Post('signIn')
  async signIn(
    @Body() signInUserDto: SignInUserDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ResponseFields> {
    return this.authService.signIn(signInUserDto, res);
  }

  @HttpCode(200)
  @Post('signOut')
  @HttpCode(HttpStatus.OK)
  async signOut(
    @GetCurrentUserId() userId: number,
    @Res({ passthrough: true }) res: Response
  ): Promise<boolean> {
    return this.authService.signOut(+userId, res);
  }

  @Post('refresh')
  @UseGuards(RefreshTokenGuard)
  @HttpCode(200)
  async refresh(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser("refreshToken") refreshToken: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ResponseFields> {
    return this.authService.refreshToken(+userId, refreshToken, res);
  }
}
