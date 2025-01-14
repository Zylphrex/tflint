# aws_elasticache_cluster_default_parameter_group

Disallow using default parameter group.

## Example

```hcl
resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "app"
  engine               = "redis"
  engine_version       = "3.2.4"
  maintenance_window   = "sun:00:00-sun:06:00"
  node_type            = "cache.m4.large"
  num_cache_nodes      = 1
  port                 = 6379
  parameter_group_name = "default.redis3.2" // default paramete group!
  subnet_group_name    = "app-subnet-group"
  security_group_ids   = ["${aws_security_group.redis.id}"]
}
```

```
$ tflint
template.tf
        NOTICE:9 "default.redis3.2" is default parameter group. You cannot edit it. (aws_elasticache_cluster_default_parameter_group)

Result: 1 issues  (0 errors , 0 warnings , 1 notices)
```

## Why

You can modify parameter values in a custom parameter group, but you can't change the parameter values in a default parameter group.

## How To Fix

Create a new parameter group, and change the `parameter_group_name` to that.
