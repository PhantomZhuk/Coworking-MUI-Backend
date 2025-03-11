import { Body, Controller, Get, Post, Req, Res, Logger } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { ApiBody, ApiOperation, ApiResponse } from '@nestjs/swagger';
import * as jwt from 'jsonwebtoken';
import { Request, Response } from 'express';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) { }

  private generateTokens(email: string) {
    const accessToken = jwt.sign({ email }, process.env.JWT_SECRET_KEY!, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ email }, process.env.JWT_REFRESH_SECRET!, { expiresIn: '30d' });
    return { accessToken, refreshToken };
  }

  private setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
    res.cookie('accessToken', accessToken, { httpOnly: true, secure: true });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true });
  }

  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiResponse({ status: 400, description: 'User registration failed' })
  @Post('register')
  async register(@Body() registerDto: RegisterDto, @Res() res: Response) {
    try {
      await this.authService.register(registerDto);
      const { accessToken, refreshToken } = this.generateTokens(registerDto.email);
      this.setAuthCookies(res, accessToken, refreshToken);
      this.logger.log(`User registered successfully: ${registerDto.email}`);
      return res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      this.logger.error('User registration failed', error.stack);
      return res.status(400).json({ message: 'User registration failed' });
    }
  }

  @ApiOperation({ summary: 'Login a user' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'User logged in successfully' })
  @ApiResponse({ status: 400, description: 'Invalid credentials' })
  @Post('login')
  async login(@Body() loginDto: LoginDto, @Res() res: Response) {
    try {
      const user = await this.authService.login(loginDto);
      const { accessToken, refreshToken } = this.generateTokens(user.email);
      this.setAuthCookies(res, accessToken, refreshToken);
      return res.status(200).json({ message: 'User logged in successfully' });
    } catch (error) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
  }

  @ApiOperation({ summary: 'Logout a user' })
  @ApiResponse({ status: 200, description: 'User logged out successfully' })
  @Post('logout')
  async logout(@Res() res: Response) {
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    return res.status(200).json({ message: 'User logged out successfully' });
  }

  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 200, description: 'Access token refreshed successfully' })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  @Get('refresh')
  async refresh(@Req() req: Request, @Res() res: Response) {
    const refreshToken = req.cookies['refreshToken'];
    if (!refreshToken) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!) as any;
      const { accessToken, refreshToken: newRefreshToken } = this.generateTokens(decoded.email);
      this.setAuthCookies(res, accessToken, newRefreshToken);
      return res.status(200).json({ message: 'Access token refreshed successfully' });
    } catch (error) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
  }

  @ApiOperation({ summary: 'Verify a token' })  
  @ApiResponse({ status: 200, description: 'Token verified successfully' })
  @ApiResponse({ status: 401, description: 'Invalid token' })
  @Get('verify')
  async verifyToken(@Req() req: Request, @Res() res: Response) {
    const accessToken = req.cookies['accessToken'];
    if (!accessToken) {
      return res.status(401).json({ message: 'Invalid access token' });
    }
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET_KEY!);
    
    if (typeof decoded === 'object' && 'email' in decoded) {
      const user = await this.authService.findUserByEmail(decoded.email as string);
      if (!user) {
        return res.status(401).json({ message: 'Invalid token' });
      }
      return res.status(200).json({ message: 'Token verified successfully' });
    } else {
      return res.status(401).json({ message: 'Invalid token' });
    }
  }
}
