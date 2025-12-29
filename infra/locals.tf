locals {
  name         = "${var.name}-${random_id.suffix.hex}"
  project_name = var.name
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      Project     = var.name
    }
  )

  # Helper function to normalize email inputs (string, list, or null) to list
  # Uses flatten() to handle both string and list inputs consistently
  normalize_emails = {
    # Convert admin_email to list, handling null, empty string, string, or list
    admins = var.admin_email != null && var.admin_email != "" ? (
      flatten([var.admin_email])
    ) : []
    # Convert request_creator_email to list
    request_creators = var.request_creator_email != null && var.request_creator_email != "" ? (
      flatten([var.request_creator_email])
    ) : []
    # Convert reviewer_email to list
    reviewers = var.reviewer_email != null && var.reviewer_email != "" ? (
      flatten([var.reviewer_email])
    ) : []
    # Convert viewer_email to list
    viewers = var.viewer_email != null && var.viewer_email != "" ? (
      flatten([var.viewer_email])
    ) : []
  }

  # Build seed_users list from normalized emails, filtering out empty strings
  seed_users = flatten([
    # Admin users
    [
      for email in local.normalize_emails.admins : {
        email      = email
        group_name = "admins"
      } if email != null && email != ""
    ],
    # Request creator users
    [
      for email in local.normalize_emails.request_creators : {
        email      = email
        group_name = "request_creators"
      } if email != null && email != ""
    ],
    # Reviewer users
    [
      for email in local.normalize_emails.reviewers : {
        email      = email
        group_name = "reviewers"
      } if email != null && email != ""
    ],
    # Viewer users
    [
      for email in local.normalize_emails.viewers : {
        email      = email
        group_name = "viewers"
      } if email != null && email != ""
    ]
  ])
}
