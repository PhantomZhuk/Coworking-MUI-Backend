import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    AuthModule,
    ConfigModule.forRoot({
      envFilePath: '.env',
      isGlobal: true,
      cache: true
    }),
    MongooseModule.forRoot(process.env.MONGODB_URI!)
  ],
  controllers: [],
  providers: [],
})
export class AppModule { }
