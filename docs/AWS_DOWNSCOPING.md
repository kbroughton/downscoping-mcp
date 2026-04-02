# AWS Downscoping

## Mechanism: `sts:GetFederationToken` with Inline Policy

AWS offers true dynamic downscoping via the Security Token Service (STS). The effective permissions of the derived session are the **intersection** of the caller's identity policies and the inline policy you supply — you can never exceed what you already have.

```
effective_permissions = caller_identity_policies ∩ inline_policy
```

This is analogous to `aws sts assume-role --policy-arns`, which restricts an assumed role to the intersection of that role's policies and the supplied policy ARNs.

**No new IAM roles are required.** The inline policy is supplied at call time in `config.yaml`.

### API call

```bash
aws sts get-federation-token \
  --name "claude-ai-session" \
  --duration-seconds 3600 \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}'
```

Returns temporary credentials (`AccessKeyId`, `SecretAccessKey`, `SessionToken`) scoped to only the permissions in the intersection.

### Difference from `assume-role`

| Feature | `get-federation-token` | `assume-role` |
|---------|----------------------|---------------|
| Requires target role ARN | No | Yes |
| Works with user credentials | Yes | Only for users allowed to assume roles |
| Inline policy | Yes | Yes |
| Policy ARNs | No | Yes |
| Max session duration | 12 h | 1 h (default) |

For most AI-assistant workflows `get-federation-token` is simpler — no role ARN to manage. Use `assume-role` if your team already has roles configured per environment.

---

## config.yaml example (sts_policy mode)

```yaml
version: 1

services:
  aws:
    downscope_mode: sts_policy
    inline_policy:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action:
            - "s3:GetObject"
            - "s3:ListBucket"
            - "s3:ListAllMyBuckets"
            - "ec2:Describe*"
            - "iam:Get*"
            - "iam:List*"
            - "logs:Describe*"
            - "logs:Get*"
            - "logs:FilterLogEvents"
          Resource: "*"
    rules:
      - name: "S3 uploads require review"
        match:
          args_pattern: "s3 (cp|mv|sync) .* s3://"
        action: review
      - name: "IAM mutations denied"
        match:
          args_pattern: "iam (create|delete|put|attach|detach|update)"
        action: deny
      - name: "destructive EC2/RDS require review"
        match:
          args_pattern: "ec2 (terminate|stop|delete)|rds (delete|stop)"
        action: review
```

---

## Fallback: token_slot mode

If STS is unavailable (e.g. the calling principal can't call `sts:GetFederationToken`), fall back to pre-provisioned credentials:

```yaml
services:
  aws:
    downscope_mode: token_slot
    token_slots:
      readonly:
        env_var: AWS_ACCESS_KEY_ID_READONLY   # IAM user with read-only policy
        inject_as: AWS_ACCESS_KEY_ID
        # Also set AWS_SECRET_ACCESS_KEY_READONLY → AWS_SECRET_ACCESS_KEY
      admin:
        env_var: AWS_ACCESS_KEY_ID_ADMIN
        inject_as: AWS_ACCESS_KEY_ID
    default_slot: readonly
```

Note: for AWS you likely also need to inject `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` alongside `AWS_ACCESS_KEY_ID`. Extend the token slot schema to include additional env var pairs as your configuration requires.

---

## Permission mapping reference

The [IAM Dataset](https://github.com/iann0036/iam-dataset) (`aws/map.json`) provides a mapping from AWS SDK methods to required IAM actions. Since the AWS CLI maps directly to SDK methods, this is useful for building `inline_policy` statements:

- `aws s3 cp` → `S3.PutObject` → `s3:PutObject`
- `aws ec2 describe-instances` → `EC2.DescribeInstances` → `ec2:DescribeInstances`
- `aws iam create-user` → `IAM.CreateUser` → `iam:CreateUser`

Browse the dataset or use [aws.permissions.cloud](https://aws.permissions.cloud) to look up permissions interactively.

---

## Security notes

- `sts:GetFederationToken` requires the caller's identity policy to explicitly allow `sts:GetFederationToken`.
- The inline policy cannot grant permissions the caller does not already have — the intersection is the hard floor.
- Sessions derived via federation cannot call `iam:*` or `sts:GetFederationToken` themselves (AWS restriction on federated sessions).
- For multi-account scenarios, use `sts:AssumeRole` into a cross-account role first, then apply the inline policy restriction.
