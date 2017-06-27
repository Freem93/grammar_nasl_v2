#TRUSTED 7162fd4ad8993737e922867477d3eb6236c99a958ed4eb994a26fb17ac625c09e6225b0be4f801023a29a6c71703710e790c3801afe67ae612f38ebf407bb1d06dda989d5d19e35944a9663222e70c19b83aa19fdedbe6e033d1e3b997f1005a2c1d31d0d89efc4cc31c8c0b997a5071573602e08a772afab874034942b2a54197458c161bf631b7dce890c7152a04ee5801e7595780751d391cb55e005b7241b85ce89874b3cf05d310008834d345dd1a9717d526cab4dbddfc2035422479c587b6519efc578366b92777527d0d58f20ced14be6c818e92bdeaec2bb4ed04e4027eb9699c01acdc8670fb01d86d707db83bcb0a4d960a69b003a1f89e9ae56c6d6200239e08da0ce40fa76960fe776bb4d8e29fa0b7a7e357f69f6da97dd9440213dfbe8df8b724f6ea5635e3e5bd49f2eb0255eb4bd73d3f1c551f7fbc05bd7747d9edfdc6e73cdf51a9be13816a2f2b44c8f841a3f7ea06c042c94952bbb8cb84c5448d07ab2d3164c1ef14566df99587be1b57220337f8dfec1c2a315076dc010433adbb50ddf2d89e873ff8d47b1aec5dbda9c43e5d83b8e95890307ba5eb5abf5513073bdd8ddcfcee4d4d2efc39c104da4799f591968c5e79dac7d3e4968ee512d911fa0680cac11853ba0d66c39e61eae3f3955a7b878e6417e249d08a10260b70132b8f9d391082cd95e7d092ac567694bc28710becd8624ed962f1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91457);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/03");

  script_cve_id("CVE-2016-3427");
  script_osvdb_id(137303);
  script_xref(name:"VMSA", value:"2016-0005");

  script_name(english:"VMware vSphere Replication Oracle JRE JMX Deserialization RCE (VMSA-2016-0005)");
  script_summary(english:"Checks the version of vSphere Replication.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a virtualization appliance that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware vSphere Replication running on the remote host is version
5.6.x prior to 5.6.0.6, 5.8.x prior to 5.8.1.2, 6.0.x prior to
6.0.0.3, or 6.1.x prior to 6.1.1. It is, therefore, affected by a
remote code execution vulnerability in the Oracle JRE JMX component
due to a flaw related to the deserialization of authentication
credentials. An unauthenticated, remote attacker can exploit this to
execute arbitrary code.

Note that vSphere Replication is only affected if its vCloud Tunneling
Agent is running, and it is not enabled by default.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0005");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vSphere Replication version 5.6.0.6 / 5.8.1.2 /
6.0.0.3 / 6.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vsphere_replication");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vSphere Replication/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

version = get_kb_item_or_exit("Host/VMware vSphere Replication/Version");
verui = get_kb_item_or_exit("Host/VMware vSphere Replication/VerUI");
build = get_kb_item_or_exit("Host/VMware vSphere Replication/Build");

fix = '';
vuln = FALSE;

if (version =~ '^5\\.6\\.' && int(build) < 3845873) fix = '5.6.0.6 Build 3845873';
else if (version =~ '^5\\.8\\.' && int(build) < 3845890) fix = '5.8.1.2 Build 3845890';
else if (version =~ '^6\\.0\\.' && int(build) < 3845888) fix = '6.0.0.3 Build 3845888';
else if (version =~ '^6\\.1\\.' && int(build) < 3849281) fix = '6.1.1 Build 3849281';

if (!empty(fix))
{
  sock_g = ssh_open_connection();
  if (! sock_g)
    audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;

  line = info_send_cmd(cmd:"service vmware-vcd status");
  if (
    "vmware-vcd-watchdog is running" >< line &&
    "vmware-vcd-cell is running" >< line
  )
  {
    vuln = TRUE;
  }
  else
    exit(0, "vCloud Tunneling Agent does not appear to be running on the VMware vSphere Replication appliance examined (Version " + verui + ").");

}

if (vuln)
{
  report =
    '\n  Installed version : ' + verui +
    '\n  Fixed version     : ' + fix +
    '\n';

   security_report_v4(
    extra    : report,
    port     : '0',
    severity : SECURITY_HOLE
  );
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vSphere Replication', verui);
