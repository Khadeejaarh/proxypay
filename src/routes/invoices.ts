import { Router, Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { TimeoutPresets, haltOnTimedout } from '../middleware/timeout';
import { InvoiceModel, InvoiceStatus, type Invoice } from '../models/invoice';
import logger from '../utils/logger';
import { s3Service } from '../services/s3';

const invoiceRoutes = Router();
const invoiceModel = new InvoiceModel();

/**
 * GET /api/invoices - List invoices for the authenticated user
 */
invoiceRoutes.get(
  '/',
  TimeoutPresets.quick,
  haltOnTimedout,
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const result = await invoiceModel.findByUserId(userId, req.query);
      res.json(result);
    } catch (err) {
      logger.error({ error: err }, 'Failed to list invoices');
      res.status(500).json({ error: 'Failed to list invoices' });
    }
  }
);

/**
 * GET /api/invoices/:id - Get a specific invoice
 */
invoiceRoutes.get(
  '/:id',
  TimeoutPresets.quick,
  haltOnTimedout,
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const userId = (req as any).user?.id;

      const invoice = await invoiceModel.findById(id);
      if (!invoice) {
        return res.status(404).json({ error: 'Invoice not found' });
      }

      // Verify ownership
      if (invoice.userId !== userId) {
        return res.status(403).json({ error: 'Access denied' });
      }

      res.json(invoice);
    } catch (err) {
      logger.error({ error: err }, 'Failed to fetch invoice');
      res.status(500).json({ error: 'Failed to fetch invoice' });
    }
  }
);

/**
 * GET /api/invoices/:id/download - Download invoice PDF
 */
invoiceRoutes.get(
  '/:id/download',
  TimeoutPresets.medium,
  haltOnTimedout,
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const userId = (req as any).user?.id;

      const invoice = await invoiceModel.findById(id);
      if (!invoice) {
        return res.status(404).json({ error: 'Invoice not found' });
      }

      // Verify ownership
      if (invoice.userId !== userId) {
        return res.status(403).json({ error: 'Access denied' });
      }

      if (invoice.status !== InvoiceStatus.Generated && invoice.status !== InvoiceStatus.Sent) {
        return res.status(400).json({ error: 'Invoice is not ready for download' });
      }

      if (!invoice.pdfStorageKey) {
        return res.status(400).json({ error: 'Invoice PDF not available' });
      }

      let pdf: Buffer;
      try {
        pdf = await s3Service.getObject(invoice.pdfStorageKey);
      } catch (storageErr) {
        logger.error(
          { error: storageErr, invoiceId: id, storageKey: invoice.pdfStorageKey },
          'Failed to retrieve invoice PDF from storage'
        );
        return res.status(502).json({ error: 'Invoice PDF could not be retrieved from storage' });
      }

      if (!pdf || pdf.length === 0) {
        return res.status(404).json({ error: 'Invoice PDF not found in storage' });
      }

      const safeFilename = `${String(invoice.invoiceNumber).replace(/[^A-Za-z0-9._-]/g, '_')}.pdf`;

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
      res.setHeader('Content-Length', String(pdf.length));
      res.status(200).send(pdf);
    } catch (err) {
      logger.error({ error: err }, 'Failed to download invoice');
      res.status(500).json({ error: 'Failed to download invoice' });
    }
  }
);

/**
 * POST /api/invoices/:id/resend - Resend invoice via email
 */
invoiceRoutes.post(
  '/:id/resend',
  TimeoutPresets.quick,
  haltOnTimedout,
  authenticateToken,
  async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const userId = (req as any).user?.id;

      const invoice = await invoiceModel.findById(id);
      if (!invoice) {
        return res.status(404).json({ error: 'Invoice not found' });
      }

      // Verify ownership
      if (invoice.userId !== userId) {
        return res.status(403).json({ error: 'Access denied' });
      }

      // TODO: Resend invoice via email
      res.json({
        message: 'Invoice resend queued',
        invoiceId: id,
        status: 'pending',
      });
    } catch (err) {
      logger.error({ error: err }, 'Failed to resend invoice');
      res.status(500).json({ error: 'Failed to resend invoice' });
    }
  }
);

/**
 * ADMIN: GET /api/admin/invoices/status - Get invoice processing status
 */
invoiceRoutes.get(
  '/admin/status',
  TimeoutPresets.quick,
  haltOnTimedout,
  authenticateToken,
  requireRole('admin'),
  async (req: Request, res: Response) => {
    try {
      const pending = await invoiceModel.countByStatus(InvoiceStatus.Pending);
      const generated = await invoiceModel.countByStatus(InvoiceStatus.Generated);
      const sent = await invoiceModel.countByStatus(InvoiceStatus.Sent);
      const failed = await invoiceModel.countByStatus(InvoiceStatus.Failed);

      res.json({
        pending,
        generated,
        sent,
        failed,
        timestamp: new Date(),
      });
    } catch (err) {
      logger.error({ error: err }, 'Failed to fetch invoice status');
      res.status(500).json({ error: 'Failed to fetch invoice status' });
    }
  }
);

/**
 * ADMIN: GET /api/admin/invoices/pending - List pending invoices
 */
invoiceRoutes.get(
  '/admin/pending',
  TimeoutPresets.quick,
  haltOnTimedout,
  authenticateToken,
  requireRole('admin'),
  async (req: Request, res: Response) => {
    try {
      const limit = Math.min(parseInt(String(req.query.limit)) || 50, 500);
      const invoices = await invoiceModel.getPendingInvoices(limit);
      res.json({ data: invoices, count: invoices.length });
    } catch (err) {
      logger.error({ error: err }, 'Failed to fetch pending invoices');
      res.status(500).json({ error: 'Failed to fetch pending invoices' });
    }
  }
);

/**
 * ADMIN: POST /api/admin/invoices/:id/cancel - Cancel an invoice
 */
invoiceRoutes.post(
  '/admin/:id/cancel',
  TimeoutPresets.quick,
  haltOnTimedout,
  authenticateToken,
  requireRole('admin'),
  async (req: Request, res: Response) => {
    try {
      const { id } = req.params;

      const invoice = await invoiceModel.findById(id);
      if (!invoice) {
        return res.status(404).json({ error: 'Invoice not found' });
      }

      const cancelled = await invoiceModel.cancel(id);
      logger.info({ invoiceId: id }, 'Invoice cancelled by admin');

      res.json({
        message: 'Invoice cancelled',
        invoice: cancelled,
      });
    } catch (err) {
      logger.error({ error: err }, 'Failed to cancel invoice');
      res.status(500).json({ error: 'Failed to cancel invoice' });
    }
  }
);

export default invoiceRoutes;
