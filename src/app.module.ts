/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AtGuard } from './auth/common/guards';
import { PrismaModule } from './prisma/prisma.module';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [AuthModule, PrismaModule],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },
  ],
})
export class AppModule {}
