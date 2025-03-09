import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Document } from "mongoose";

@Schema()
export class User extends Document {
    @Prop({ required: true, unique: true })
    email: string;

    @Prop({ required: true })
    password: string;

    @Prop({ required: true })
    name: string;

    @Prop({ required: true })
    role: string;

    @Prop({ required: true, default: Date.now })
    createdAt: Date;

    @Prop({ required: true, default: Date.now })
    updatedAt: Date;

    @Prop()
    phoneNumber?: string;

    @Prop()
    profilePictureUrl?: string;

    @Prop({ type: [String], default: [] })
    favoriteSpaces?: string[];

    @Prop({ default: false })
    isVerified?: boolean;

    @Prop({ type: [String], default: [] })
    bookings?: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);