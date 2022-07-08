import { ApiProperty } from '@nestjs/swagger';
import { IsDateString, IsDefined, IsInt, IsOptional, IsString } from 'class-validator';
import { Exclude } from 'class-transformer';

export class ProfileDto {
    @Exclude()
    id: number;

    @ApiProperty({
        type: Number,
        description: 'The ID of the user'
    })
    @IsDefined()
    userID: number;

    @ApiProperty({
        type: String,
        description: 'The text-based bio of the user'
    })
    @IsString()
    bio: string;

    @ApiProperty({
        type: Number,
        description: 'The ID of the badge of the user'
    })
    @IsOptional()
    @IsInt()
    featuredBadgeID: number;

    @ApiProperty()
    @IsDefined()
    @IsDateString()
    createdAt: Date;

    @ApiProperty()
    @IsDateString()
    updatedAt: Date;
}