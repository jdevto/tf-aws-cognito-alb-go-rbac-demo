variable "name" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "enable_versioning" {
  description = "Enable versioning for the S3 bucket"
  type        = bool
  default     = false
}

variable "force_destroy" {
  description = "Force destroy the S3 bucket"
  type        = bool
  default     = false
}

variable "tags" {
  description = "A map of tags to assign to the resources"
  type        = map(string)
  default     = {}
}

variable "upload_files" {
  description = "Configuration for uploading files to S3. Set to null to disable file uploads."
  type = object({
    source_dir   = string
    file_pattern = string
    s3_prefix    = optional(string)
    content_types = optional(map(string), {
      ".py"   = "text/x-python"
      ".sh"   = "text/x-shellscript"
      ".txt"  = "text/plain"
      ".json" = "application/json"
      ".yaml" = "text/yaml"
      ".yml"  = "text/yaml"
      ".md"   = "text/markdown"
    })
  })
  default = null
}
