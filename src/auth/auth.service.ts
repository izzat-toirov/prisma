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

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly usersService: UsersService,
  ) {}

  private async generateTokens(user: User) {
    const payload = {
      id: user.id,
      email: user.email,
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

  async signIn(signInUserDto: SignInUserDto, res: Response) {
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

  async signOut(refreshToken: string, res: Response) {
    let userData: any;
    try {
      userData = await this.jwtService.verify(refreshToken, {
        secret: process.env.REFRESH_TOKEN_KEY,
      });
    } catch (error) {
      throw new BadRequestException('Refresh token noto‘g‘ri yoki eskirgan');
    }

    await this.usersService.uptadeRefreshToken(userData.id, "");
    res.clearCookie('refreshToken');

    return {
      message: 'Foydalanuvchi tizimdan chiqdi',
    };
  }

  async refreshToken(
    userId: number,
    refreshTokenFromCookie: string,
    res: Response,
  ) {
    const decodedToken = this.jwtService.decode(refreshTokenFromCookie) as {
      id: number;
      email: string;
    };

    if (!decodedToken || userId !== decodedToken.id) {
      throw new ForbiddenException('Ruxsat etilmagan');
    }

    const user = await this.usersService.findOne(userId);
    if (!user || !user.hashedRefreshToken) {
      throw new NotAcceptableException('Foydalanuvchi topilmadi');
    }

    const tokenMatch = await bcrypt.compare(
      refreshTokenFromCookie,
      user.hashedRefreshToken,
    );

    if (!tokenMatch) {
      throw new ForbiddenException('Refresh token mos emas');
    }

    const { accessToken, refreshToken } = await this.generateTokens(user);
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 12);

    await this.usersService.uptadeRefreshToken(user.id, hashedRefreshToken);

    res.cookie('refreshToken', refreshToken, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    return {
      message: 'Token yangilandi',
      userId: user.id,
      accessToken,
    };
  }
}
