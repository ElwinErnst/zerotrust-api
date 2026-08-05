import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

export class GeneratePolicyDto {
  @IsString()
  @MinLength(3)
  @MaxLength(1000)
  intent!: string;

  @IsOptional()
  @IsString()
  @MaxLength(120)
  tenantSlug?: string;
}
