import { Request, Response } from 'express';
import { gdprService } from '../../services/gdpr/gdpr.service';
import { purgePreviewStore } from '../../services/gdpr/purge-preview.store';
import { logger } from '../../utils/logger';

export class GdprController {
  async exportUserData(req: Request, res: Response): Promise<void> {
    const { userId } = req.params;
    try {
      const result = await gdprService.exportUserData(userId);
      res.status(200).json(result);
    } catch (err) {
      logger.error('GDPR export failed', { userId, err });
      res.status(500).json({ error: 'Failed to export user data' });
    }
  }

  async previewPurge(req: Request, res: Response): Promise<void> {
    const { userId } = req.params;
    try {
      const preview = await gdprService.previewPurge(userId);
      const previewId = purgePreviewStore.save(userId, preview);
      res.status(200).json({ previewId, ...preview });
    } catch (err) {
      logger.error('GDPR purge preview failed', { userId, err });
      res.status(500).json({ error: 'Failed to preview user data purge' });
    }
  }

  async purgeUserData(req: Request, res: Response): Promise<void> {
    const { userId } = req.params;
    const { previewId, confirm } = req.body ?? {};

    if (confirm !== true) {
      res.status(400).json({ error: 'Explicit confirmation required to purge user data' });
      return;
    }

    const preview = previewId ? purgePreviewStore.get(previewId) : undefined;
    if (!preview || preview.userId !== userId) {
      res.status(400).json({ error: 'A valid previewId for this user is required before purging' });
      return;
    }

    try {
      const executionId = await gdprService.purgeUserData(userId, { previewId });
      purgePreviewStore.markExecuted(previewId, executionId);
      res.status(200).json({ executionId, previewId });
    } catch (err) {
      logger.error('GDPR purge failed', { userId, previewId, err });
      res.status(500).json({ error: 'Failed to purge user data' });
    }
  }
}

export const gdprController = new GdprController();
