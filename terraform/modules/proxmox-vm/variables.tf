variable "vm_name"     { type = string }
variable "vm_id"       { type = number }
variable "target_node" { type = string }
variable "template"    { type = string }
variable "cores"       { type = number; default = 2 }
variable "memory"      { type = number; default = 4096 }
variable "disk_size"   { type = string; default = "40G" }
variable "ip_address"  { type = string }
variable "gateway"     { type = string }
variable "nameserver"  { type = string }
variable "ssh_keys"    { type = string }
variable "tags"        { type = list(string); default = [] }
