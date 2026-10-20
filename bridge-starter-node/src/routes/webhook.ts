import { Router, Request, Response } from "express";
import { verifyWebhookSignature } from "../middleware/verifySignature";
import { WebhookEvent, PaymentData } from "../types/webhook";
import logger from "../logger";

const router = Router();

// SEP-31 payout idempotency: track the persisted transaction reference and the
// terminal state we have already reconciled so duplicate or out-of-order
// completion callbacks cannot trigger a second payout submission.
type PayoutState = "pending" | "completed" | "failed";

interface PayoutRecord {
  reference: string;
  state: PayoutState;
}

const payoutsByReference = new Map<string, PayoutRecord>();

function resolveReference(event: WebhookEvent<PaymentData>): string | undefined {
  const data = event.data as (PaymentData & { reference?: string }) | undefined;
  return data?.reference ?? data?.id;
}

router.post(
  "/webhook",
  verifyWebhookSignature,
  (req: Request, res: Response) => {
    const event = req.body as WebhookEvent<PaymentData>;

    logger.info(
      { eventType: event.type },
      "Webhook received",
    );

    const reference = resolveReference(event);

    switch (event.type) {
      case "payment.success": {
        const existing = reference ? payoutsByReference.get(reference) : undefined;

        if (existing && existing.state === "completed") {
          logger.info(
            { eventType: event.type, reference },
            "Duplicate completion callback ignored",
          );
          break;
        }

        if (reference) {
          payoutsByReference.set(reference, { reference, state: "completed" });
        }

        logger.info(
          {
            eventType: event.type,
            reference,
            paymentId: event.data?.id,
            amount: event.data?.amount,
            status: event.data?.status,
          },
          "Payment succeeded",
        );
        break;
      }

      case "payment.failed": {
        const existing = reference ? payoutsByReference.get(reference) : undefined;

        if (existing && existing.state === "completed") {
          logger.warn(
            { eventType: event.type, reference },
            "Out-of-order failure callback ignored for completed payout",
          );
          break;
        }

        if (reference) {
          payoutsByReference.set(reference, { reference, state: "failed" });
        }

        logger.warn(
          {
            eventType: event.type,
            reference,
            paymentId: event.data?.id,
            amount: event.data?.amount,
            status: event.data?.status,
          },
          "Payment failed",
        );
        break;
      }

      default:
        logger.warn(
          { eventType: event.type },
          "Unhandled webhook event type",
        );
    }

    res.status(200).json({ received: true });
  },
);

export default router;
