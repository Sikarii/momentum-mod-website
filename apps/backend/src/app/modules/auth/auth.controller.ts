import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  RawBodyRequest,
  Redirect,
  Req,
  Res,
  UseGuards,
  VERSION_NEUTRAL
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags
} from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { FastifyReply, FastifyRequest } from 'fastify';
import { JwtAuthService } from './jwt/jwt-auth.service';
import { SteamOpenIDService } from './steam/steam-openid.service';
import { BypassJwtAuth, LoggedInUser } from '@momentum/backend/decorators';
import { SteamWebGuard } from './steam/steam-web.guard';
import { SteamGameGuard } from './steam/steam-game.guard';
import {
  JWTResponseGameDto,
  JWTResponseWebDto,
  RefreshTokenDto
} from '@momentum/backend/dto';
import { CookieSerializeOptions } from '@fastify/cookie';

@Controller({
  path: 'auth',
  version: VERSION_NEUTRAL
})
@ApiTags('Auth')
@ApiBearerAuth()
export class AuthController {
  private readonly cookieOptions: CookieSerializeOptions;

  constructor(
    private readonly authService: JwtAuthService,
    private readonly configService: ConfigService,
    private readonly steamOpenID: SteamOpenIDService
  ) {
    this.cookieOptions = {
      domain: this.configService.get('domain'),
      // The value on the cookies gets transferred to local storage immediately,
      // so just use a short lifetime of 10s.
      maxAge: this.configService.get('jwt.expTime'),
      path: '/',
      // So frontend can access. Cookie is deleted immediately so never
      // retrurned to the backend, so no CSRF risk.
      httpOnly: true
    };
  }

  //#region Main Auth

  @Get('/web')
  @Redirect('', HttpStatus.FOUND)
  @BypassJwtAuth()
  @ApiOperation({
    summary:
      'Initiates a browser-based OpenID login workflow using the Steam portal'
  })
  async steamWebAuth() {
    return { url: await this.steamOpenID.getRedirectUrl() };
  }

  @Get('/web/return')
  @Redirect('/dashboard', HttpStatus.FOUND)
  @BypassJwtAuth()
  @UseGuards(SteamWebGuard)
  @ApiOperation({ summary: 'Assigns a JWT using OpenID data from Steam login' })
  async steamWebAuthReturn(
    @Res({ passthrough: true }) res: FastifyReply,
    @LoggedInUser() user
  ) {
    const jwt = await this.authService.loginWeb(user);

    res.setCookie('accessToken', jwt.accessToken, this.cookieOptions);
    res.setCookie('refreshToken', jwt.refreshToken, {
      ...this.cookieOptions,
      maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days, TODO: should this be in the config
    });
  }

  @Post('/game')
  @BypassJwtAuth()
  @UseGuards(SteamGameGuard)
  @ApiOperation({
    summary: 'Assigns a JWT using user ticket from the Momentum client'
  })
  @ApiBody({
    type: 'application/octet-stream',
    description: 'Octet-stream of a Steam user auth ticket from Steam',
    required: true
  })
  @ApiOkResponse({
    type: JWTResponseGameDto,
    description: 'Authorized steam user token'
  })
  async steamGameAuth(
    @Req() req: RawBodyRequest<FastifyRequest>,
    @LoggedInUser() user
  ): Promise<JWTResponseGameDto> {
    return this.authService.loginGame(user);
  }

  @BypassJwtAuth()
  @Post('/refresh')
  @ApiOperation({
    summary: 'Generate a new access token for a given refresh token'
  })
  @ApiBody({ type: RefreshTokenDto })
  @ApiOkResponse({
    type: JWTResponseWebDto,
    description: 'Refreshed web tokens'
  })
  async refreshToken(
    @Req() req,
    @Res({ passthrough: true }) res: FastifyReply
  ) {
    const refreshToken = req.cookies.refreshToken;
    const jwt = await this.authService.refreshRefreshToken(refreshToken);

    res.setCookie('accessToken', jwt.accessToken, this.cookieOptions);

    // TODO: This should not be necessary as soon as frontend
    // code does not rely on this anymore
    return jwt;
  }

  @Post('/revoke')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revokes the given token' })
  @ApiBody({ type: RefreshTokenDto })
  @ApiNoContentResponse()
  async revokeToken(
    @Req() req,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const refreshToken = req.cookies.refreshToken;
    await this.authService.revokeRefreshToken(refreshToken);

    res.clearCookie('accessToken', this.cookieOptions);
    res.clearCookie('refreshToken', this.cookieOptions);
  }

  //#endregion
}
