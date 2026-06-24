import { IsString, IsEmail, Matches, IsOptional, IsIn } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class VerifyOtpDto {
  @ApiProperty({
    description: "Email address",
    example: "user@example.com",
  })
  @IsString()
  @IsEmail()
  email!: string;

  @ApiProperty({
    description: "OTP code (4-6 digits)",
    example: "123456",
    pattern: "^\\d{4,6}$",
  })
  @IsString()
  @Matches(/^\d{4,6}$/)
  otp!: string;

  @ApiProperty({
    description:
      "Verification ID received when OTP was sent (optional, for additional validation)",
    example: "5040166",
    required: false,
  })
  @IsString()
  @IsOptional()
  verificationId?: string;

  @ApiProperty({
    description:
      "Purpose of the verification (login or register). " +
      "If 'login', returns 404 for unregistered users. " +
      "If 'register', returns 409 for already registered users.",
    example: "login",
    required: false,
    enum: ["login", "register"],
  })
  @IsString()
  @IsOptional()
  @IsIn(["login", "register"])
  purpose?: "login" | "register";
}
