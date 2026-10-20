import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { Readable } from 'stream';

const s3 = new S3Client({ region: process.env.AWS_REGION || 'us-east-1' });
const bucket = process.env.S3_BUCKET || '';

export interface StoredObject {
  body: Readable;
  contentType?: string;
  contentLength?: number;
}

export class StorageError extends Error {
  statusCode: number;
  constructor(message: string, statusCode = 502) {
    super(message);
    this.name = 'StorageError';
    this.statusCode = statusCode;
  }
}

export async function getObject(key: string): Promise<StoredObject> {
  try {
    const result = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    if (!result.Body) {
      throw new StorageError('Stored object has no body', 502);
    }
    return {
      body: result.Body as Readable,
      contentType: result.ContentType,
      contentLength: result.ContentLength,
    };
  } catch (err) {
    if (err instanceof StorageError) throw err;
    const name = (err as { name?: string }).name;
    if (name === 'NoSuchKey' || name === 'NotFound') {
      throw new StorageError('Stored object not found', 404);
    }
    throw new StorageError('Failed to retrieve stored object', 502);
  }
}
