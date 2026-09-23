resource "aws_security_group" "audit_recovery_client" {
  name        = "${var.name}-audit-recovery-client"
  description = "Gateway-only identity for audit recovery storage"
  vpc_id      = aws_vpc.main.id
  tags        = var.tags
}

resource "aws_security_group" "audit_recovery" {
  name        = "${var.name}-audit-recovery"
  description = "NFS access to durable gateway audit recovery"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.audit_recovery_client.id]
  }

  tags = var.tags
}

resource "aws_efs_file_system" "audit_recovery" {
  encrypted  = true
  kms_key_id = aws_kms_key.main.arn
  tags       = merge(var.tags, { Name = "${var.name}-audit-recovery" })
}

resource "aws_efs_mount_target" "audit_recovery" {
  for_each        = aws_subnet.private
  file_system_id  = aws_efs_file_system.audit_recovery.id
  subnet_id       = each.value.id
  security_groups = [aws_security_group.audit_recovery.id]
}

resource "aws_efs_access_point" "audit_recovery" {
  file_system_id = aws_efs_file_system.audit_recovery.id

  posix_user {
    uid = 65532
    gid = 65532
  }

  root_directory {
    path = "/gateway"
    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "0700"
    }
  }

  tags = var.tags
}

resource "aws_efs_backup_policy" "audit_recovery" {
  file_system_id = aws_efs_file_system.audit_recovery.id
  backup_policy { status = "ENABLED" }
}
