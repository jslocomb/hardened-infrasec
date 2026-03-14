variable "vm_name"     { type = string }
variable "vm_id"       { type = number }
variable "target_node" { type = string }
variable "template_id" { type = number }
variable "datastore"   { type = string; default = "local-lvm" }
variable "cores"       { type = number; default = 2 }
variable "memory"      { type = number; default = 4096 }
variable "disk_size"   { type = number; default = 40 }
variable "ip_address"  { type = string }
variable "gateway"     { type = string }
variable "nameserver"  { type = string }
variable "ssh_keys"    { type = list(string) }
variable "tags"        { type = list(string); default = [] }
