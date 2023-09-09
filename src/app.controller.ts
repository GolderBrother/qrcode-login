import {
  BadRequestException,
  Controller,
  Get,
  Inject,
  Query,
  Headers,
  UnauthorizedException,
} from '@nestjs/common';
import { AppService } from './app.service';
import { randomUUID } from 'crypto';
import * as qrcode from 'qrcode';
import { JwtService } from '@nestjs/jwt';

// const map = new Map<string, QrCodeInfo>();

enum QrCodeStatus {
  /** 未扫描 */
  NO_SCAN = 'noscan',
  /** 已扫描，等待用户确认 */
  SCAN_WAIT_CONFIRM = 'scan-wait-confirm',
  /** 已扫描，用户同意授权 */
  SCAN_CONFIRM = 'scan-confirm',
  /** 已扫描，用户取消授权 */
  SCAN_CANCEL = 'scan-cancel',
  /** 已过期 */
  EXPIRED = 'expired',
}
interface QrCodeInfo {
  status: QrCodeStatus;
  userInfo?: {
    id: number;
  };
}

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Inject(JwtService)
  private jwtService: JwtService;

  private users = [
    { id: 1, username: 'james', password: '111' },
    { id: 2, username: 'zhang', password: '222' },
  ];

  private map = new Map<string, QrCodeInfo>();

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('qrcode/generate')
  async generateQrcode() {
    const uuid = randomUUID();
    const text = `http://192.168.31.131:3000/pages/confirm.html?id=${uuid}`;
    const dataUrl = await qrcode.toDataURL(text);
    this.map.set(`qrcode_${uuid}`, {
      status: QrCodeStatus.NO_SCAN,
    });
    return {
      qrcode_id: uuid,
      img: dataUrl,
    };
  }

  @Get('qrcode/check')
  async checkQrcode(@Query('id') id: string) {
    const info = this.map.get(`qrcode_${id}`);
    if (!info) {
      throw new BadRequestException('二维码已过期');
    }
    console.log('info', info);
    if (info.status === 'scan-confirm') {
      return {
        token: await this.jwtService.sign({
          userId: info.userInfo.id,
        }),
        ...info,
      };
    }
    return info;
  }

  @Get('qrcode/scan')
  async scanQrcode(@Query('id') id: string) {
    const info = this.map.get(`qrcode_${id}`);
    if (!info) {
      throw new BadRequestException('二维码已过期');
    }
    info.status = QrCodeStatus.SCAN_WAIT_CONFIRM;
    return 'success';
  }

  @Get('qrcode/confirm')
  async confirmQrcode(
    @Query('id') id: string,
    @Headers('Authorization') auth: string,
  ) {
    const userInfo = await this.getUserInfoByAuth(auth);
    console.log('auth', auth);
    console.log('userInfo', userInfo);
    const info = this.map.get(`qrcode_${id}`);
    if (!info) {
      throw new BadRequestException('二维码已过期');
    }
    info.status = QrCodeStatus.SCAN_CONFIRM;
    info.userInfo = userInfo;
    return 'success';
  }

  @Get('qrcode/cancel')
  async cancelQrcode(@Query('id') id: string) {
    const info = this.map.get(`qrcode_${id}`);
    if (!info) {
      throw new BadRequestException('二维码已过期');
    }
    info.status = QrCodeStatus.SCAN_CANCEL;
    return 'success';
  }

  @Get('login')
  async login(
    @Query('username') username: string,
    @Query('password') password: string,
  ) {
    const user = this.users.find((item) => item.username === username);
    // 用户不存在
    if (!user) {
      throw new UnauthorizedException('用户不存在');
    }
    // 密码错误
    if (user.password !== password) {
      throw new UnauthorizedException('密码错误');
    }

    const token = await this.jwtService.sign({
      userId: user.id,
    });
    return {
      token,
    };
  }

  @Get('userInfo')
  async userInfo(@Headers('Authorization') auth: string) {
    // 从 header 中取出 token，解析出其中的信息，从而拿到 userId，然后查询 id 对应的用户信息返回
    return await this.getUserInfoByAuth(auth);
  }

  /**
   * 根据token，解析出其中的信息，从而拿到 userId，然后查询 id 对应的用户信息返回
   * @param auth
   * @returns
   */
  private async getUserInfoByAuth(auth: string) {
    try {
      const [, token] = auth.split(' ');
      const info = await this.jwtService.verify(token);
      const user = this.users.find((item) => item.id === info.userId);
      return user;
    } catch (error) {
      throw new UnauthorizedException('token 过期，请重新登录');
    }
  }
}
