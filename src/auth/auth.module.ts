import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PrismaModule } from '../prisma/prisma.module';
import { UsersModule } from '../users/users.module';
import { AcessTokenStrategy, RefreshTokenStrategy } from '../common/strategies';

@Module({
  imports:[JwtModule.register({}), PrismaModule, UsersModule],
  controllers: [AuthController],
  providers: [AuthService, AcessTokenStrategy, RefreshTokenStrategy]
})
export class AuthModule {}
