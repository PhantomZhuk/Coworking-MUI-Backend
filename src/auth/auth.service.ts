import { ConflictException, Injectable, Logger } from '@nestjs/common';
import { User } from 'src/common/schemas/user.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);

    constructor(
        @InjectModel(User.name) private userModel: Model<User>
    ) {}

    async register(registerDto: RegisterDto) {
        const { email, password, name, phoneNumber } = registerDto;
        const existingUser = await this.userModel.findOne({ email });
        if (existingUser) {
            this.logger.warn(`Registration attempt with existing email: ${email}`);
            throw new ConflictException('User already exists');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await this.userModel.create({ email, password: hashedPassword, name, phoneNumber });
        this.logger.log(`User registered successfully: ${email}`);
        return user;
    }

    async login(loginDto: LoginDto) {
        const { email, password } = loginDto;
        const user = await this.userModel.findOne({ email });
        if (!user) {
            this.logger.warn(`Login attempt with invalid email: ${email}`);
            throw new ConflictException('Invalid credentials');
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            this.logger.warn(`Login attempt with invalid password: ${email}`);
            throw new ConflictException('Invalid credentials');
        }
        this.logger.log(`User logged in successfully: ${email}`);
        return user;
    }

    async findUserByEmail(email: string) {
        return this.userModel.findOne({ email });
    }
}
