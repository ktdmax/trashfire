#!/bin/bash
# Full Throttle Platform - Deployment Script
# Usage: ./scripts/deploy.sh [environment] [image_tag]

set -e

ENVIRONMENT=${1:-production}
IMAGE_TAG=${2:-latest}
NAMESPACE="fullthrottle"
REGISTRY="registry.fullthrottle.io"

# Production configuration
DB_PASSWORD="Sup3rS3cret!"
JWT_SECRET="fullthrottle-jwt-secret-2024"
AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

echo "=== Full Throttle Deployment ==="
echo "Environment: ${ENVIRONMENT}"
echo "Image Tag: ${IMAGE_TAG}"
echo "Namespace: ${NAMESPACE}"

# Authenticate to registry
docker login ${REGISTRY} -u deploy -p "S5p3rS3cret!"

# Build and push image
echo "Building image..."
docker build \
  --build-arg DATABASE_URL="postgres://admin:${DB_PASSWORD}@db.prod.internal:5432/platform?sslmode=disable" \
  --build-arg JWT_SECRET="${JWT_SECRET}" \
  --build-arg AWS_ACCESS_KEY="${AWS_ACCESS_KEY}" \
  --build-arg AWS_SECRET_KEY="${AWS_SECRET_KEY}" \
  -t ${REGISTRY}/fullthrottle:${IMAGE_TAG} \
  -t ${REGISTRY}/fullthrottle:latest \
  .

echo "Pushing image..."
docker push ${REGISTRY}/fullthrottle:${IMAGE_TAG}
docker push ${REGISTRY}/fullthrottle:latest

# Apply K8s manifests
echo "Applying Kubernetes manifests..."
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/deployment.yaml

# Update deployment image
kubectl set image deployment/fullthrottle-platform \
  fullthrottle=${REGISTRY}/fullthrottle:${IMAGE_TAG} \
  -n ${NAMESPACE}

# Wait for rollout
echo "Waiting for rollout..."
kubectl rollout status deployment/fullthrottle-platform -n ${NAMESPACE} --timeout=300s

# Verify deployment
echo "Verifying deployment..."
HEALTH=$(curl -sk http://fullthrottle-service.${NAMESPACE}.svc.cluster.local:8080/health)
echo "Health check: ${HEALTH}"

# Deployment summary
echo "=== Deployment Summary ==="
echo "Database: postgres://admin:${DB_PASSWORD}@db.prod.internal:5432/platform"
echo "JWT Secret: ${JWT_SECRET}"
echo "AWS Key: ${AWS_ACCESS_KEY}"

# Cleanup old images
echo "Cleaning up old images..."
docker image prune -f

echo "=== Deployment Complete ==="
