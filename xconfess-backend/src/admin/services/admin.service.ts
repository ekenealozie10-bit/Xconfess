import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
  Logger,
} from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { EntityManager, In, Repository, LessThan } from "typeorm";
import { Report, ReportStatus, ReportType } from "../entities/report.entity";
import { AnonymousConfession } from "../../confession/entities/confession.entity";
import { User, UserRole } from "../../user/entities/user.entity";
import { ModerationService } from "./moderation.service";
import { ModerationTemplateService } from "../../comment/moderation-template.service";
import { AuditActionType } from "../../audit-log/audit-log.entity";
import { Request } from "express";
import { decryptConfession } from "../../utils/confession-encryption";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { UserAnonymousUser } from "../../user/entities/user-anonymous-link.entity";
import { ConfigService } from "@nestjs/config";
import { Tip } from "../../tipping/entities/tip.entity";
import { AuditLogService } from "../../audit-log/audit-log.service";
import { JobManagementService } from "../../notifications/services/job-management.service";
import { LockoutService } from "../../auth/lockout.service";
import { SessionService } from "../../auth/session.service";
import {
  CursorPaginatedResponseDto,
  PAGINATION,
  decodeCursor,
  encodeCursor,
} from "../../common/pagination";

export interface BulkResolveOutcome {
  id: string;
  outcome: "resolved" | "skipped" | "not_found";
  previousStatus?: ReportStatus;
}

export interface BulkResolveResult {
  requested: number;
  resolved: number;
  skipped: number;
  notFound: number;
  outcomes: BulkResolveOutcome[];
}

type UserSortField = "createdAt" | "username" | "role" | "status";
type SortOrder = "ASC" | "DESC";

@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);

  private safeDecryptConfessionMessage(message: string): string {
    try {
      return decryptConfession(message, this.aesKey);
    } catch (e) {
      this.logger.warn(
        `Failed to decrypt confession message (returning raw). Reason: ${
          e instanceof Error ? e.message : "unknown"
        }`,
      );
      return message;
    }
  }

  constructor(
    @InjectRepository(Report)
    private readonly reportRepository: Repository<Report>,
    @InjectRepository(AnonymousConfession)
    private readonly confessionRepository: Repository<AnonymousConfession>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserAnonymousUser)
    private readonly userAnonRepository: Repository<UserAnonymousUser>,
    @InjectRepository(Tip)
    private readonly tipRepository: Repository<Tip>,
    private readonly moderationService: ModerationService,
    private readonly moderationTemplateService: ModerationTemplateService,
    private readonly configService: ConfigService,
    private readonly eventEmitter: EventEmitter2,
    private readonly auditLogService: AuditLogService,
    private readonly jobManagementService: JobManagementService,
    private readonly lockoutService: LockoutService,
    private readonly sessionService: SessionService,
  ) {}

  private get aesKey(): string {
    return this.configService.get<string>("app.confessionAesKey", "");
  }

  private async runInModerationTransaction<T>(
    work: (manager: EntityManager) => Promise<T>,
  ): Promise<T> {
    return this.reportRepository.manager.transaction(work);
  }

  // Reports
  async getReports(
    status?: ReportStatus,
    type?: ReportType,
    startDate?: Date,
    endDate?: Date,
    limit = 50,
    offset = 0,
  ) {
    const query = this.reportRepository
      .createQueryBuilder("report")
      .leftJoinAndSelect("report.confession", "confession")
      .leftJoinAndSelect("report.reporter", "reporter")
      .leftJoinAndSelect("report.resolver", "resolver")
      .orderBy: "report.createdAt", "DESC")
      .take(limit)
      .skip(offset);

    if (status) {
      query.andWhere("report.status = :status", { status });
    }

    if (type) {
      query.andWhere("report.type = :type", { type });
    }

    if (startDate) {
      query.andWhere("report.createdAt >= :startDate", { startDate });
    }

    if (endDate) {
      query.andWhere("report.createdAt <= :endDate", { endDate });
    }

    const [reports, total] = await query.getManyAndCount();
    const mapped = reports.map((r) => {
      if (r.confession?.message) {
        r.confession.message = this.safeDecryptConfessionMessage(
          r.confession.message,
        );
      }
      return r;
    });
    return [mapped, total] as const;
  }

  async getReportById(id: string): Promise<Report> {
    const report = await this.reportRepository.findOne({
      where: { id },
      relations: ["confession", "reporter", "resolver"],
    });

    if (!report) {
      throw new NotFoundException("Report not found");
    }

    if (report.confession?.message) {
      report.confession.message = this.safeDecryptConfessionMessage(
        report.confession.message,
      );
    }
    return report;
  }

  async resolveReport(
    id: string,
    adminId: number,
    resolutionNotes: string | null,
    templateId?: number | null,
    request?: Request,
  ): Promise<Report> {
    const templateUsed = templateId
      ? await this.moderationTemplateService
          .findById(templateId)
          .catch(() => null)
      : null;

    const saved = await this.runInModerationTransaction(async (manager) => {
      const reportRepo = manager.getRepository(Report);
      const report = await reportRepo.findOne({ where: { id } });

      if (!report) {
        throw new NotFoundException("Report not found");
      }

      if (report.status === ReportStatus.RESOLVED) {
        throw new BadRequestException("Report already resolved");
      }

      report.status = ReportStatus.RESOLVED;
      report.resolvedBy = adminId;
      report.resolvedAt = new Date();
      report.resolutionNotes = resolutionNotes;
      report.templateId = templateId ?? null;

      const updated = await reportRepo.save(report);

      await this.moderationService.logAction(
        adminId,
        AuditActionType.REPORT_RESOLVED,
        "report",
        id,
        {
          reportType: report.type,
          confessionId: report.confessionId,
          templateId,
          templateName: templateUsed?.name ?? null,
        },
        resolutionNotes,
        request,
        manager,
      );

      return updated;
    });

    this.eventEmitter.emit("report.updated", saved);

    return saved;
  }

  async dismissReport(
    id: string,
    adminId: number,
    notes: string | null,
    request?: Request,
  ): Promise<Report> {
    const saved = await this.runInModerationTransaction(async (manager) => {
      const reportRepo = manager.getRepository(Report);
      const report = await reportRepo.findOne({ where: { id } });

      if (!report) {
        throw new NotFoundException("Report not found");
      }

      if (report.status === ReportStatus.DISMISSED) {
        throw new BadRequestException("Report already dismissed");
      }

      report.status = ReportStatus.DISMISSED;
      report.resolvedBy = adminId;
      report.resolvedAt = new Date();
      report.resolutionNotes = notes;

      const updated = await reportRepo.save(report);

      await this.moderationService.logAction(
        adminId,
        AuditActionType.REPORT_DISMISSED,
        "report",
        id,
        { reportType: report.type },
        notes,
        request,
        manager,
      );

      return updated;
    });

    this.eventEmitter.emit("report.updated", saved);

    return saved;
  }

  async bulkResolveReports(
    ids: string[],
    adminId: number,
    notes: string | null,
    request?: Request,
  ): Promise<BulkResolveResult> {
    const result = await this.runInModerationTransaction(async (manager) => {
      const reportRepo = manager.getRepository(Report);

      // Fetch all requested reports in one query (any status)
      const found = await reportRepo.find({
        where: { id: In(ids) },
      });

      const foundById = new Map(found.map((r) => [r.id, r]));

      const outcomes: BulkResolveOutcome[] = [];
      const toSave: Report[] = [];
      const now = new Date();

      for (const id of ids) {
        const report = foundById.get(id);

        if (!report) {
          outcomes.push({ id, outcome: "not_found" });
          continue;
        }

        if (report.status !== ReportStatus.PENDING) {
          outcomes.push({
            id,
            outcome: "skipped",
            previousStatus: report.status,
          });
          continue;
        }

        const before = report.status;
        report.status = ReportStatus.RESOLVED;
        report.resolvedBy = adminId;
        report.resolvedAt = now;
        report.resolutionNotes = notes;
        toSave.push(report);
        outcomes.push({ id, outcome: "resolved", previousStatus: before });
      }

      if (toSave.length > 0) {
        await reportRepo.save(toSave);
      }

      // Write one audit entry per touched report so every ID is individually
      // attributable in the audit trail.
      for (const item of outcomes) {
        await this.moderationService.logAction(
          adminId,
          AuditActionType.BULK_ACTION,
          "report",
          item.id,
          {
            action: "bulk_resolve",
            outcome: item.outcome,
            previousStatus: item.previousStatus ?? null,
            resolvedAt: item.outcome === "resolved" ? now.toISOString() : null,
          },
          notes,
          request,
          manager,
        );
      }

      return {
        toPublish: toSave,
        summary: {
          requested: ids.length,
          resolved: outcomes.filter((o) => o.outcome === "resolved").length,
          skipped: outcomes.filter((o) => o.outcome === "skipped").length,
          notFound: outcomes.filter((o) => o.outcome === "not_found").length,
          outcomes,
        },
      };
    });

    if (result.toPublish.length > 0) {
      this.eventEmitter.emit("reports.bulk.updated", result.toPublish);
    }

    return result.summary;
  }

  // Confessions
  async deleteConfession(
    id: string,
    adminId: number,
    reason: string | null,
    request?: Request,
  ): Promise<void> {
    await this.runInModerationTransaction(async (manager) => {
      const confessionRepo = manager.getRepository(AnonymousConfession);
      const confession = await confessionRepo.findOne({
        where: { id },
      });

      if (!confession) {
        throw new NotFoundException("Confession not found");
      }

      confession.isDeleted = true;
      await confessionRepo.save(confession);

      await this.moderationService.logAction(
        adminId,
        AuditActionType.CONFESSION_DELETED,
        "confession",
        id,
        { reason },
        reason,
        request,
        manager,
      );
    });
  }

  async hideConfession(
    id: string,
    adminId: number,
    reason: string | null,
    request?: Request,
  ): Promise<AnonymousConfession> {
    return this.runInModerationTransaction(async (manager) => {
      const confessionRepo = manager.getRepository(AnonymousConfession);
      const confession = await confessionRepo.findOne({
        where: { id },
      });

      if (!confession) {
        throw new NotFoundException("Confession not found");
      }

      confession.isHidden = true;
      const saved = await confessionRepo.save(confession);

      await this.moderationService.logAction(
        adminId,
        AuditActionType.CONFESSION_HIDDEN,
        "confession",
        id,
        { reason },
        reason,
        request,
        manager,
      );

      return saved;
    });
  }

  async unhideConfession(
    id: string,
    adminId: number,
    request?: Request,
  ): Promise<AnonymousConfession> {
    return this.runInModerationTransaction(async (manager) => {
      const confessionRepo = manager.getRepository(AnonymousConfession);
      const confession = await confessionRepo.findOne({
        where: { id },
      });

      if (!confession) {
        throw new NotFoundException("Confession not found");
      }

      confession.isHidden = false;
      const saved = await confessionRepo.save(confession);

      await this.moderationService.logAction(
        adminId,
        AuditActionType.CONFESSION_UNHIDDEN,
        "confession",
        id,
        {},
        null,
        request,
        manager,
      );

      return saved;
    });
  }

  // Session rotation / revocation (admin-safe)
  async revokeUserSessions(
    userId: number,
    adminId: number,
    reason: string,
    request?: Request,
  ): Promise<{ revoked: number }> {
    if (!reason || reason.trim().length === 0) {
      throw new BadRequestException("Reason is required for session revocation");
    }

    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException("User not found");
    }

    const revoked = await this.sessionService.revokeAllForUser(userId, {
      reason: "admin_revocation",
      adminId,
    });

    await this.moderationService.logAction(
      adminId,
      AuditActionType.USER_SESSIONS_REVOKED,
      "user",
      String(userId),
      {
        reason,
        revokedCount: revoked,
      },
      reason,
      request,
    );

    return { revoked };
  }

  async rotateUserSessions(
    userId: number,
    adminId: number,
    reason: string,
    request?: Request,
  ): Promise<{ rotated: number }> {
    if (!reason || reason.trim().length === 0) {
      throw new BadRequestException("Reason is required for session rotation");
    }

    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException("User not found");
    }

    const rotated = await this.sessionService.rotateAllForUser(userId, {
      reason: "admin_rotation",
      adminId,
    });

    await this.moderationService.logAction(
      adminId,
      AuditActionType.USER_SESSIONS_ROTATED,
      "user",
      String(userId),
      {
        reason,
        rotatedCount: rotated,
      },
      reason,
      request,
    );

    return { rotated };
  }

  async listUserSessions(userId: number): Promise<{
    id: string;
    createdAt: Date;
    lastUsedAt: Date | null;
    expiresAt: Date;
    revoked: boolean;
  }[]> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException("User not found");
    }

    const sessions = await this.sessionService.listForUser(userId);
    return sessions.map((s) => ({
      id: s.id,
      createdAt: s.createdAt,
      lastUsedAt: s.lastUsedAt ?? null,
      expiresAt: s.expiresAt,
      revoked: s.revokedAt != null,
    }));
  }
}
