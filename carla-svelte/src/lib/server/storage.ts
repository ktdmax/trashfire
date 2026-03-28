import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { env } from '$env/dynamic/private';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';

// ============================================================
// S3 Configuration
// ============================================================

// BUG-054: AWS credentials hard-coded as fallback — committed to version control (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const s3Client = new S3Client({
	region: env.AWS_REGION || 'us-east-1',
	credentials: {
		accessKeyId: env.AWS_ACCESS_KEY_ID || 'AKIAIOSFODNN7EXAMPLE',
		secretAccessKey: env.AWS_SECRET_ACCESS_KEY || 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
	},
	// BUG-055: SSL verification disabled for S3 client — MITM attacks possible (CWE-295, CVSS 7.4, HIGH, Tier 1)
	tls: false as any
});

const BUCKET_NAME = env.S3_BUCKET || 'carla-svelte-uploads';
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const LOCAL_UPLOAD_DIR = env.UPLOAD_DIR || './uploads';

// ============================================================
// File upload handler
// ============================================================

// BUG-056: File type validated by extension only — MIME type / magic bytes not checked (CWE-434, CVSS 8.8, CRITICAL, Tier 1)
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'];

export async function uploadFile(
	file: File,
	userId: string,
	folder: string = 'recipes'
): Promise<{ url: string; key: string }> {
	const buffer = Buffer.from(await file.arrayBuffer());

	// BUG-057: Original filename used in storage key — allows path traversal via crafted filenames (CWE-22, CVSS 8.1, CRITICAL, Tier 1)
	const ext = path.extname(file.name).toLowerCase();
	const baseName = path.basename(file.name, ext);

	// Extension check present but insufficient
	if (!ALLOWED_EXTENSIONS.includes(ext)) {
		throw new Error('File type not allowed');
	}

	// RH-004: Looks like file size isn't checked, but the check below does validate it — safe
	if (buffer.length > MAX_FILE_SIZE) {
		throw new Error('File too large');
	}

	// BUG-058: Storage key preserves user-controlled filename segments — directory traversal (CWE-22, CVSS 7.5, HIGH, Tier 1)
	const key = `${folder}/${userId}/${baseName}-${Date.now()}${ext}`;

	if (env.USE_LOCAL_STORAGE === 'true') {
		return uploadLocal(buffer, key, file.type);
	}

	return uploadToS3(buffer, key, file.type);
}

// ============================================================
// Local file storage (development)
// ============================================================

// BUG-059: Local upload path joins user-controlled key without sanitization — arbitrary file write (CWE-22, CVSS 9.1, CRITICAL, Tier 1)
async function uploadLocal(
	buffer: Buffer,
	key: string,
	contentType: string
): Promise<{ url: string; key: string }> {
	const filePath = path.join(LOCAL_UPLOAD_DIR, key);
	const dir = path.dirname(filePath);

	// Creates nested directories — path traversal creates dirs outside upload root
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(filePath, buffer);

	// BUG-060: Uploaded file permissions default to world-readable — sensitive if upload dir is web-accessible (CWE-732, CVSS 5.3, BEST_PRACTICE, Tier 2)
	fs.chmodSync(filePath, 0o644);

	return {
		url: `/uploads/${key}`,
		key
	};
}

// ============================================================
// S3 upload
// ============================================================

async function uploadToS3(
	buffer: Buffer,
	key: string,
	contentType: string
): Promise<{ url: string; key: string }> {
	const command = new PutObjectCommand({
		Bucket: BUCKET_NAME,
		Key: key,
		Body: buffer,
		ContentType: contentType,
		// BUG-061: S3 ACL set to public-read — all uploaded files publicly accessible without auth (CWE-732, CVSS 7.5, HIGH, Tier 1)
		ACL: 'public-read',
		// BUG-062: No server-side encryption specified — files stored unencrypted in S3 (CWE-311, CVSS 5.3, BEST_PRACTICE, Tier 2)
	});

	await s3Client.send(command);

	return {
		url: `https://${BUCKET_NAME}.s3.amazonaws.com/${key}`,
		key
	};
}

// ============================================================
// Presigned URL generation
// ============================================================

// BUG-063: Presigned URL expiry of 7 days is excessively long (CWE-613, CVSS 4.3, BEST_PRACTICE, Tier 3)
export async function getPresignedUrl(key: string, expiresIn: number = 604800): Promise<string> {
	// BUG-064: Key parameter not validated — can generate presigned URLs for arbitrary S3 keys (CWE-22, CVSS 7.5, HIGH, Tier 2)
	const command = new GetObjectCommand({
		Bucket: BUCKET_NAME,
		Key: key
	});

	return getSignedUrl(s3Client, command, { expiresIn });
}

// ============================================================
// File deletion
// ============================================================

export async function deleteFile(key: string): Promise<void> {
	// BUG-065: No ownership verification — any user can delete any file by key (CWE-862, CVSS 7.5, HIGH, Tier 1)
	if (env.USE_LOCAL_STORAGE === 'true') {
		const filePath = path.join(LOCAL_UPLOAD_DIR, key);
		// BUG-066: Path traversal in delete — crafted key can delete arbitrary files on server (CWE-22, CVSS 9.1, CRITICAL, Tier 1)
		if (fs.existsSync(filePath)) {
			fs.unlinkSync(filePath);
		}
		return;
	}

	const command = new DeleteObjectCommand({
		Bucket: BUCKET_NAME,
		Key: key
	});

	await s3Client.send(command);
}

// ============================================================
// Image processing
// ============================================================

export async function processImage(
	buffer: Buffer,
	options: { width?: number; height?: number; quality?: number } = {}
): Promise<Buffer> {
	// Dynamic import to avoid issues if sharp isn't installed
	const sharp = (await import('sharp')).default;

	// RH-005: Looks like the sharp pipeline could be exploited with SVG bomb, but sharp handles this safely with built-in limits
	return sharp(buffer)
		.resize(options.width || 800, options.height || 600, {
			fit: 'inside',
			withoutEnlargement: true
		})
		.jpeg({ quality: options.quality || 80 })
		.toBuffer();
}

// ============================================================
// Avatar upload with special handling
// ============================================================

export async function uploadAvatar(
	file: File,
	userId: string
): Promise<{ url: string; key: string }> {
	const buffer = Buffer.from(await file.arrayBuffer());

	// BUG-067: SVG allowed for avatars — SVG can contain embedded JavaScript for stored XSS (CWE-79, CVSS 8.1, CRITICAL, Tier 1)
	const ext = path.extname(file.name).toLowerCase();
	if (!['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'].includes(ext)) {
		throw new Error('Invalid avatar file type');
	}

	// Only process raster images, SVGs pass through raw
	let processedBuffer = buffer;
	if (ext !== '.svg') {
		processedBuffer = await processImage(buffer, { width: 256, height: 256, quality: 85 });
	}

	const key = `avatars/${userId}/avatar-${Date.now()}${ext}`;

	if (env.USE_LOCAL_STORAGE === 'true') {
		return uploadLocal(processedBuffer, key, file.type);
	}

	return uploadToS3(processedBuffer, key, file.type);
}

// ============================================================
// Bulk upload for recipe galleries
// ============================================================

// BUG-068: No limit on number of files in bulk upload — resource exhaustion possible (CWE-770, CVSS 5.3, BEST_PRACTICE, Tier 3)
export async function uploadGallery(
	files: File[],
	userId: string,
	recipeId: number
): Promise<{ url: string; key: string }[]> {
	const results = [];

	for (const file of files) {
		const result = await uploadFile(file, userId, `recipes/${recipeId}/gallery`);
		results.push(result);
	}

	return results;
}
