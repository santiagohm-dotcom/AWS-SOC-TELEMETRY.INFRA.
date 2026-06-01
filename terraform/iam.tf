# ==============================================================================
# AWS IAM Configuration - Least Privilege Instance Roles
# ==============================================================================

# 1. Define the Trust Policy allowing EC2 instances to assume this role
data "aws_iam_policy_document" "ec2_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# 2. Create the IAM Role for the SOC Laboratory EC2 Instances
resource "aws_iam_role" "soc_instance_role" {
  name               = "soc-laboratory-instance-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role_policy.json

  force_detach_policies = true

  tags = {
    Name = "soc-instance-role"
  }
}

# 3. Attach a core Read-Only managed policy
resource "aws_iam_role_policy_attachment" "ssm_core_attachment" {
  role       = aws_iam_role.soc_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# 4. Create the IAM Instance Profile container that Terraform binds to EC2
resource "aws_iam_instance_profile" "soc_instance_profile" {
  name = "soc-laboratory-instance-profile"
  role = aws_iam_role.soc_instance_role.name
}