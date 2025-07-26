import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto, UpdateUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { User } from '../../generated/prisma';

@Injectable()
export class UsersService {
  constructor(private readonly prismaService: PrismaService) {}
  async create(createUserDto: CreateUserDto) {
    const { name, email, phone, password, confirm_password } = createUserDto;
    if (password != confirm_password) {
      throw new BadRequestException('Parollar mos emas');
    }
    const hashedPassword = await bcrypt.hash(password!, 7);
    return this.prismaService.user.create({
      data: {
        name,
        email,
        phone,
        hashedPassword,
      },
    });
  }

  findAll() {
    return this.prismaService.user.findMany();
  }

  findOne(id: number) {
    return this.prismaService.user.findUnique({where: {id}});
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return this.prismaService.user.update({where: {id}, data:updateUserDto});
  }

  remove(id: number) {
    return this.prismaService.user.delete({where: {id}});
  }

  async findUserByEmail(email: string, id: number) {
    return await this.prismaService.user.findUnique({ where: { email } });
  }
  
  async uptadeRefreshToken(id: number, refreshToken: string) {
    const updatedUser = await this.prismaService.user.update({
      where: { id },
      data: { hashedRefreshToken: refreshToken },
    });
  
    return updatedUser;
  }
  



}
