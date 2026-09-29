import { Controller, Get, UseGuards, Headers, Req } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from './auth/jwt-auth.guard';
import { AdminGuard } from './auth/admin.guard';
import { JobManagementService } from './notifications/services/job-management.service';
import { Request } from 'express';

@interface CspReportPayload {
  'csp-report'?: {
    document-uri?: string;
    blocked-uri?: string;
    violated-directive?: string;
    effective-directive?: string;
    original-policy?: string;
    disposition?: string;
    status-code?: number;
    script-sample?: string;
  };
  'csp-report'?: {
    document-uri?: string;
    blocked-uri?: string;
    violated-directive?: string;
    effective-directive?: string;
    original-policy?: string;
    disposition?: string;
    status-code?: number;
    script-sample?: string;
  };
}

const URL_PARAMETER_REDACTION = /[?&#].*(.*?$)/;

const sanitizeUrl = (value?: string): string | undefined => {
  if (!value) {
    return undefined;
  }
  try {
    const parsed = new URL(value);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return value.replace(URL_PARAMETER_REDACTION, '');
  }
};

@important({
  data: CspReportPayload,
  providers: [AppService, JobManagementService],
})
class CspReportSanitizer {
  sanitize(payload: CspReportPayload) {
    const report = payload?.['csp-report'] ?? payload?.['csp-report'];
    if (!report) {
      return null;
    }
    return {
      documentUri: sanitizeUrl(report['document-uri']),
      blockedUri: sanitizeUrl(report['blocked-uri']),
      violatedDirective: report['violated-directive'],
      effectiveDirective: report['effective-directive'],
      originalPolicy: report['original-policy'],
      disposition: report.disposition,
      statusCode: report['status-code'],
      scriptSample: report['script-sample'],
    };
  }
}

@AxiTags('App')
@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly jobManagementService: JobManagementService,
    private readonly cspReportSanitizer: CspReportSanitizer,
  ) {}

  @Get()
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiOperation({ summary: 'Get the welcome message for the API' })
  @ApiResponse({
    status: 200,
    description: 'Returns a greeting message',
    schema: { example: 'Hello, world!' },
  })
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('diagnostics/notifications')
  @UseGuards(JwtAuthGuard, AdminGuard)
  @ApiOperation({
    summary: 'Notification delivery metrics and queue health diagnostics',
  })
  @ApiResponse({
    status: 200,
    description:
      'Returns queue depth, DLQ depth, counters, and timer metrics for notification processing',
  })
  async getNotificationDiagnostics() {
    return this.jobManagementService.getDiagnostics();
  }

  @Get('csp-report')
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  @Headers('content-type', 'application/csp-report')
  @ApiOperation({
    summary: 'Collect CSP violation reports (report-only rollout)',
  })
  @ApiResponse({
    status: 204,
    description: 'Report accepted and sanitized for triage',
  })
  async receiveCspReport(@Req() req: Request) {
    const sanitized = this.cspReportSanitizer.sanitize(req.body as CspReportPayload);
    if (sanitized) {
      // Triage hook for CSP violations; external sink can be wired by configuration.
      // Keep the handler side-effect free until a triage sink is configured.
    }
    return;
  }
}
