import { Router } from "express";
import multer from "multer";
import { ReconciliationController } from "../controllers/reconciliationController";
// import { authenticateAdmin } from "../middleware/auth"; // Assuming there's admin auth

const MAX_CSV_SIZE = 10 * 1024 * 1024; // 10MB

const router = Router();
// Multipart uploads bypass express.json's REQUEST_SIZE_LIMIT, so this route
// declares its own byte limit and CSV-only content filter.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_CSV_SIZE, files: 1, fields: 5, fieldSize: 64 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (
      file.mimetype === "text/csv" ||
      file.mimetype === "application/vnd.ms-excel" ||
      String(file.originalname || "").toLowerCase().endsWith(".csv")
    ) {
      cb(null, true);
      return;
    }
    cb(new Error("Invalid file type. Only CSV uploads are accepted"));
  },
});
const controller = new ReconciliationController();

// Manual upload
router.post(
  "/upload",
  // authenticateAdmin,
  upload.single("file"),
  (err: Error, _req: unknown, res: any, next: any) => {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        res.status(413).json({
          error: `File size exceeds maximum limit of ${MAX_CSV_SIZE / (1024 * 1024)}MB`,
        });
        return;
      }
      res.status(400).json({ error: err.message });
      return;
    }
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    }
    next();
  },
  controller.uploadAndReconcile
);

// List reports
router.get("/reports", controller.getReports);

// Report details & discrepancies
router.get("/reports/:id", controller.getReportDetails);

// Resolve discrepancy
router.patch("/discrepancies/:id/resolve", controller.resolveDiscrepancy);

export default router;
