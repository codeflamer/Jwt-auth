/* eslint-disable prettier/prettier */
import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
      },
    });
    const token: Tokens = await this.getTokens(user.id, dto.email);
    await this.updateRefreshToken(user.id, token.refresh_token);
    return {
      access_token: token.access_token,
      refresh_token: token.refresh_token,
    };
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Credentials Incorrect');
    const passwordMatches = bcrypt.compare(dto.password, user.hash);
    if (!passwordMatches) throw new ForbiddenException('Access denied');

    const token: Tokens = await this.getTokens(user.id, dto.email);
    await this.updateRefreshToken(user.id, token.refresh_token);
    return {
      access_token: token.access_token,
      refresh_token: token.refresh_token,
    };
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async refreshTokens(userId: number, refreshToken: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied');
    const rtMatch = await bcrypt.compare(refreshToken, user.hashedRt);
    if (!rtMatch) {
      throw new ForbiddenException('Access Denied');
    }
    const token = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, token.refresh_token);
    return token;
  }

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async updateRefreshToken(userId: number, refreshToken: string) {
    const hash = await this.hashData(refreshToken);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      await this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'at-token',
          expiresIn: 60 * 15,
        },
      ),
      await this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'rt-token',
          expiresIn: 60 * 60 * 24 * 7,
        },
      ),
    ]);

    return { access_token: at, refresh_token: rt };
  }
}
