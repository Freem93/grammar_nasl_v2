#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58792);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

  script_cve_id("CVE-2012-1518");
  script_bugtraq_id(53006);
  script_osvdb_id(81163);
  script_xref(name:"VMSA", value:"2012-0007");

  script_name(english:"VMware Fusion 4.x < 4.1.2 (VMSA-2012-0007)");
  script_summary(english:"Checks version of Fusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion 4.x installed on the Mac OS X host is
earlier than 4.1.2.  As such, it is reportedly affected by a local
privilege escalation vulnerability because the access control list of
the VMware Tools folder is incorrectly set.

By exploiting this issue, a local attacker could elevate his privileges
on Windows-based Guest Operating Systems.");

  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0007.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000172.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Fusion 4.1.2 or later. 

In addition to patching, VMware Tools must be updated on all Windows
guest VMs in order to completely mitigate the vulnerability.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "MacOSX/Fusion/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Fusion/Version");
fixed_version = "4.1.2";

if (version =~ '^4\\.' && ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Fusion", version);
