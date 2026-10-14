# Terraform (not written yet)

The testbed spec asks for Terraform that creates only the VPS, a firewall
and an SSH key for one cloud provider, and outputs an Ansible inventory.
No provider has been chosen, so there is no Terraform code here yet.

Until there is, create the VPS by hand (Ubuntu 24.04, 1 vCPU / 1 GB is
enough for a controller or a gateway), add your SSH key, and write
`deploy/ansible/inventory.ini` from `deploy/ansible/inventory.example.ini`.

When a provider is picked, the module should:

- create one controller, the gateways and the clients, with the SSH key;
- allow only SSH in the provider's firewall, leaving the egressa ports
  to ufw, which Ansible configures (deploy/ansible/roles/firewall);
- output the inventory in the format of `inventory.example.ini`, with
  `gateway_id=` on gateways;
- keep its state out of git (`.gitignore` already ignores
  `deploy/terraform/**/*.tfstate*`, `.terraform/` and `terraform.tfvars`).
