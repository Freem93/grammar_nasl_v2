#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58793);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2012-1518");
  script_bugtraq_id(53006);
  script_osvdb_id(81163);
  script_xref(name:"VMSA", value:"2012-0007");

  script_name(english:"VMware Player Local Privilege Escalation (VMSA-2012-0007)");
  script_summary(english:"Checks vulnerable versions of VMware products");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware Player installation detected on the remote host is 4.0.x
earlier than 4.0.2 and thus is potentially affected by a local
privilege escalation vulnerability because the access control list of
the VMware Tools folder is incorrectly set. 

By exploiting this issue, a local attacker could elevate his
privileges on Windows-based Guest Operating Systems.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0007.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000172.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player 4.0.2 or later. 

In addition to patching, VMware Tools must be updated on all non-
Windows guest VMs in order to completely mitigate the
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Player/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");


version = get_kb_item_or_exit("VMware/Player/Version");
fix = '4.0.2';

if (version =~ '^4\\.' && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0) 
  {
    report +=
      '\n  Installed version : '+version+
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Player", version);
