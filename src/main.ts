import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cors from 'cors';
import helmet from 'helmet';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as dotenv from 'dotenv';
dotenv.config();

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cors(
    {
      origin: "http://localhost:5173",
      credentials: true,
    }
  ))
    .use(helmet({
      contentSecurityPolicy: false,
      frameguard: { action: 'deny' },
      referrerPolicy: { policy: 'no-referrer' },
    }))
    .useGlobalPipes(new ValidationPipe({ whitelist: true }))
    .use(cookieParser());
  const config = new DocumentBuilder()
    .setTitle('🔥 Coworking MUI API') 
    .setDescription('Documentation API for Coworking MUI')
    .setVersion('1.0')
    .addBearerAuth() 
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
    customSiteTitle: 'Coworking MUI API Docs',
    customCss: `
      .topbar-wrapper img {content:url('https://your-logo-url.com/logo.png'); width:100px;}
      .swagger-ui .topbar { background-color: #1e293b; }
    `,
  });
  await app.listen(process.env.PORT ?? 5000);
  console.log(`Application is running on: ${await app.getUrl()}`);
}
bootstrap();