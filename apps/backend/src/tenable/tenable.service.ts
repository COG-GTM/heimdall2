import {Injectable} from '@nestjs/common';
import axios from 'axios';
import {Request} from 'express';
import {ConfigService} from '../config/config.service';
import {validateTenableHostUrl} from './tenable-host-url.util';

interface TenableCredentials {
  host_url: string;
  accesskey: string;
  secretkey: string;
}

// NestJS service that performs proxied requests to Tenable using credentials stored in the session
@Injectable()
export class TenableService {
  constructor(private readonly configService: ConfigService) {}

  async proxyRequest(req: Request, creds: TenableCredentials) {
    // Re-validate the session-stored host URL before proxying (SSRF defense).
    const validatedHostUrl = await validateTenableHostUrl(
      creds.host_url,
      this.configService.getTenableHostUrl()
    );

    const axiosInstance = axios.create({
      baseURL: validatedHostUrl,
      maxRedirects: 0,
      headers: {
        'x-apikey': `accesskey=${creds.accesskey}; secretkey=${creds.secretkey}`,
        'Content-Type': req.get('content-type') || 'application/json'
      }
    });

    const method = req.method;
    const url = req.originalUrl.replace('/api/tenable', '');
    const data = req.body;
    const params = req.query;

    return axiosInstance({
      method,
      url,
      data,
      params,
      responseType:
        method === 'POST' && req.get('content-type')?.includes('zip')
          ? 'arraybuffer'
          : 'json'
    });
  }
}
