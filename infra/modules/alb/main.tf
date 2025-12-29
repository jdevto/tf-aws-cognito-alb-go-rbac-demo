# =============================================================================
# SECURITY GROUP FOR APPLICATION LOAD BALANCER
# =============================================================================

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP"
    from_port   = var.http_listener_port
    to_port     = var.http_listener_port
    protocol    = "tcp"
    cidr_blocks = var.alb_ingress_cidrs
  }

  ingress {
    description = "HTTPS"
    from_port   = var.https_listener_port
    to_port     = var.https_listener_port
    protocol    = "tcp"
    cidr_blocks = var.alb_ingress_cidrs
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.name}-alb-sg"
  })
}

# =============================================================================
# APPLICATION LOAD BALANCER
# =============================================================================

resource "aws_lb" "this" {
  name               = "${var.name}-alb"
  internal           = var.internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.subnet_ids

  enable_deletion_protection = var.enable_deletion_protection
  enable_http2               = var.enable_http2

  tags = merge(var.tags, {
    Name = "${var.name}-alb"
  })
}

# =============================================================================
# TARGET GROUP
# =============================================================================

resource "aws_lb_target_group" "this" {
  name        = "${var.name}-tg"
  port        = var.target_port
  protocol    = var.target_protocol
  vpc_id      = var.vpc_id
  target_type = var.target_type

  health_check {
    enabled             = true
    healthy_threshold   = var.health_check_healthy_threshold
    unhealthy_threshold = var.health_check_unhealthy_threshold
    timeout             = var.health_check_timeout
    interval            = var.health_check_interval
    path                = var.health_check_path
    protocol            = var.health_check_protocol
    matcher             = var.health_check_matcher
    port                = "traffic-port"
  }

  deregistration_delay = var.deregistration_delay

  tags = merge(var.tags, {
    Name = "${var.name}-tg"
  })
}

# =============================================================================
# TARGET GROUP ATTACHMENT
# =============================================================================

resource "aws_lb_target_group_attachment" "this" {
  count            = var.create_target_attachments ? length(var.target_instance_ids) : 0
  target_group_arn = aws_lb_target_group.this.arn
  target_id        = var.target_instance_ids[count.index]
  port             = var.target_port
}

# =============================================================================
# HTTP LISTENER - REDIRECT TO HTTPS
# =============================================================================

resource "aws_lb_listener" "http" {
  count             = var.enable_http_listener ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = var.http_listener_port
  protocol          = "HTTP"

  # Redirect HTTP -> HTTPS
  default_action {
    type = "redirect"

    redirect {
      port        = tostring(var.https_listener_port)
      protocol    = "HTTPS"
      status_code = var.http_redirect_status_code
    }
  }
}

# =============================================================================
# HTTPS LISTENER WITH OPTIONAL COGNITO AUTH
# =============================================================================

resource "aws_lb_listener" "https" {
  count             = var.enable_https_listener && var.certificate_arn != null ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = var.https_listener_port
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = var.certificate_arn

  # Optional Cognito authentication action
  dynamic "default_action" {
    for_each = var.enable_cognito_auth ? [1] : []
    content {
      type  = "authenticate-cognito"
      order = 1

      authenticate_cognito {
        user_pool_arn       = var.cognito_user_pool_arn
        user_pool_client_id = var.cognito_user_pool_client_id
        user_pool_domain    = var.cognito_user_pool_domain

        session_cookie_name        = var.cognito_session_cookie_name
        session_timeout            = var.cognito_session_timeout
        on_unauthenticated_request = var.cognito_on_unauthenticated_request
        scope                      = var.cognito_scope
      }
    }
  }

  # Forward to target group (with or without Cognito in front)
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
    order            = var.enable_cognito_auth ? 2 : 1
  }
}

# =============================================================================
# LISTENER RULES - BYPASS AUTH FOR STATIC FILES
# =============================================================================

# Allow unauthenticated access to static files (favicon, etc.)
resource "aws_lb_listener_rule" "static_files" {
  count        = var.enable_cognito_auth ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  condition {
    path_pattern {
      values = ["/static/*", "/favicon.ico", "/favicon.svg"]
    }
  }
}

# Health check bypass (ALB already does this, but explicit is good)
resource "aws_lb_listener_rule" "health_check" {
  count        = var.enable_cognito_auth ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 101

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  condition {
    path_pattern {
      values = ["/health"]
    }
  }
}
