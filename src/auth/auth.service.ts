import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotAcceptableException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { CreateUserDto, SignInUserDto } from '../users/dto';
import { UsersService } from '../users/users.service';
import { User } from '../../generated/prisma';
import * as bcrypt from 'bcrypt';
import { Response } from 'express';
import { JWTPload, ResponseFields, Tokens } from '../common/types';
import { use } from 'passport';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly usersService: UsersService,
  ) {}

  private async generateTokens(user: User): Promise<Tokens> {
    const payload: JWTPload = {
      id: user.id,
      email: user.email,
      is_active: user.is_active
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  async signUp(createUserDto: CreateUserDto) {
    const { email } = createUserDto;
    const candidate = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (candidate) {
      throw new ConflictException('Bunday foydalanuvchi allaqachon mavjud');
    }

    const newUser = await this.usersService.create(createUserDto);
    return {
      message: 'Yangi foydalanuvchi muvaffaqiyatli yaratildi',
      userId: newUser.id,
    };
  }

  async signIn(signInUserDto: SignInUserDto, res: Response): Promise<ResponseFields> {
    const { email, password } = signInUserDto;
    const user = await this.prismaService.user.findUnique({ where: { email } });

    if (!user) {
      throw new UnauthorizedException('Bunday foydalanuvchi mavjud emas');
    }

    const isMatch = await bcrypt.compare(password, user.hashedPassword);
    if (!isMatch) {
      throw new UnauthorizedException('Email yoki parol noto‘g‘ri');
    }

    const { accessToken, refreshToken } = await this.generateTokens(user);
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 12);

    await this.prismaService.user.update({
      where: { id: user.id },
      data: { hashedRefreshToken },
    });

    res.cookie('refreshToken', refreshToken, {
      maxAge: +process.env.COOKIE_TIME!,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    return {
      message: 'Foydalanuvchi tizimga kirdi',
      userId: user.id,
      accessToken,
    };
  }

  async signOut(userId: number, res: Response) {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.hashedRefreshToken) {
      throw new ForbiddenException('User topilmadi yoki token yoq');
    }

    await this.prismaService.user.update({
      where: { id: userId },
      data: { hashedRefreshToken: null },
    },);

    if (!user) {
      throw new ForbiddenException("access deleted")
    }
    res.clearCookie('refreshToken');

    return { message: 'Foydalanuvchi tizimdan chiqdi', userId };
  }


  async refresh_token(
    userId: number,
    refreshToken: string,
    res: Response
  ): Promise<ResponseFields> {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });
    if (!user || !user.hashedRefreshToken || !user.hashedRefreshToken)
      throw new UnauthorizedException("User topilmadi");

    const rtMatches = await bcrypt.compare(
      refreshToken,
      user.hashedRefreshToken
    );

    if (!rtMatches) throw new UnauthorizedException("Refresh token noto‘g‘ri");

    const tokens: Tokens = await this.generateTokens(user);
    const hashedRefreshToken = await bcrypt.hash(tokens.refreshToken, 7);
    await this.prismaService.user.update({
      where: { id: userId },
      data: { hashedRefreshToken },
    });

    res.cookie("refreshToken", tokens.refreshToken, {
      maxAge: +process.env.REFRESH_TOKEN_TIME!,
      httpOnly: true,
    });

    return {
      message: "tokenlar yangilandi",
      userId: user.id,
      accessToken: tokens.accessToken,
    };
  }

}
