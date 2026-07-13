import { HttpException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import {
  isBlockedAddress,
  validateTenableHostUrl,
} from './tenable-host-url.util';

describe('validateTenableHostUrl', () => {
  describe('with an operator-configured Tenable host', () => {
    const configured = 'https://tenable.example.com:8443';

    it('should accept a host URL matching the configured origin', async () => {
      await expect(
        validateTenableHostUrl('https://tenable.example.com:8443/', configured),
      ).resolves.toEqual('https://tenable.example.com:8443');
    });

    it('should reject a host URL that does not match the configured origin', async () => {
      await expect(
        validateTenableHostUrl('http://169.254.169.254', configured),
      ).rejects.toThrow(HttpException);
    });

    it('should reject an attacker-chosen host even if it is public', async () => {
      await expect(
        validateTenableHostUrl('https://attacker.example.net', configured),
      ).rejects.toThrow(HttpException);
    });
  });

  describe('without an operator-configured Tenable host', () => {
    it('should reject non-http(s) schemes', async () => {
      await expect(
        validateTenableHostUrl('file:///etc/passwd'),
      ).rejects.toThrow(HttpException);
      await expect(validateTenableHostUrl('gopher://internal')).rejects.toThrow(
        HttpException,
      );
    });

    it('should reject plain http (non-https) URLs', async () => {
      await expect(
        validateTenableHostUrl('http://tenable.example.com'),
      ).rejects.toThrow(HttpException);
    });

    it('should reject invalid URLs', async () => {
      await expect(validateTenableHostUrl('not a url')).rejects.toThrow(
        HttpException,
      );
    });

    it('should reject URLs containing a path, query, fragment, or credentials', async () => {
      // Fragment trick used to discard the /rest/currentUser suffix
      await expect(
        validateTenableHostUrl(
          'https://169.254.169.254/latest/meta-data/iam/security-credentials/role#',
        ),
      ).rejects.toThrow(HttpException);
      await expect(
        validateTenableHostUrl('https://tenable.example.com/?x=1'),
      ).rejects.toThrow(HttpException);
      await expect(
        validateTenableHostUrl('https://user:pass@tenable.example.com'),
      ).rejects.toThrow(HttpException);
    });

    it('should reject the cloud metadata endpoint', async () => {
      await expect(
        validateTenableHostUrl('https://169.254.169.254'),
      ).rejects.toThrow(HttpException);
    });

    it('should reject loopback and private IP literals', async () => {
      for (const target of [
        'https://127.0.0.1',
        'https://10.0.0.5',
        'https://172.16.1.1',
        'https://192.168.1.1',
        'https://[::1]',
        'https://[::ffff:169.254.169.254]',
      ]) {
        await expect(validateTenableHostUrl(target)).rejects.toThrow(
          HttpException,
        );
      }
    });

    it('should reject hostnames that resolve to blocked addresses', async () => {
      // localhost resolves to 127.0.0.1 / ::1
      await expect(validateTenableHostUrl('https://localhost')).rejects.toThrow(
        HttpException,
      );
    });

    it('should accept a public IP literal over https', async () => {
      await expect(
        validateTenableHostUrl('https://8.8.8.8'),
      ).resolves.toEqual('https://8.8.8.8');
    });
  });
});

describe('isBlockedAddress', () => {
  it('should block private, loopback, link-local, and metadata ranges', () => {
    for (const address of [
      '127.0.0.1',
      '10.1.2.3',
      '100.64.0.1',
      '169.254.169.254',
      '172.31.255.255',
      '192.168.0.1',
      '0.0.0.0',
      '224.0.0.1',
      '::1',
      '::',
      'fe80::1',
      'fd00::1',
      '::ffff:10.0.0.1',
    ]) {
      expect(isBlockedAddress(address)).toBe(true);
    }
  });

  it('should allow public addresses', () => {
    for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
      expect(isBlockedAddress(address)).toBe(false);
    }
  });

  it('should block non-IP inputs', () => {
    expect(isBlockedAddress('not-an-ip')).toBe(true);
  });
});
