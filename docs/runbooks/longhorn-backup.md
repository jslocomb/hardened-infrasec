# Runbook: Longhorn Backup & Restore

## Configure Backup Target (S3 or NFS)

In Longhorn UI (`https://longhorn.lab.internal`):
- Settings → Backup Target → `s3://your-bucket@us-east-1/longhorn`
- Settings → Backup Target Credential Secret → (create AWS credentials secret)

## Manual Backup
```bash
# Backup a specific volume
kubectl -n longhorn-system create -f - <<EOF
apiVersion: longhorn.io/v1beta2
kind: Backup
metadata:
  name: manual-backup-$(date +%Y%m%d)
  namespace: longhorn-system
spec:
  snapshotName: <snapshot-name>
EOF
```

## Restore from Backup
```bash
# Create a volume from backup in Longhorn UI:
# Backup → Select backup → Restore
# Specify new PVC name and namespace
```

## Scheduled Backups
Configure in Longhorn UI: Volumes → Select Volume → Recurring Jobs → Add Schedule
- Type: Backup
- Cron: `0 2 * * *` (2 AM daily)
- Retain: 7
