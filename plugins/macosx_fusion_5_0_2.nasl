#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64919);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/04 12:02:45 $");

  script_cve_id("CVE-2013-1406");
  script_bugtraq_id(57867);
  script_osvdb_id(90019);
  script_xref(name:"VMSA", value:"2013-0002");

  script_name(english:"VMware Fusion 4.1 < 4.1.4 / 5.0 < 5.0.2 VMCI Privilege Escalation (VMSA-2013-0002)");
  script_summary(english:"Checks version of Fusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the Mac OS X host is a
version prior to 4.1.4 / 5.0.2.  It is, therefore, reportedly affected
by a privilege escalation vulnerability in the Virtual Machine
Communication Interface (VMCI). 

By exploiting this issue, a local attacker could elevate their
privileges on Windows-based hosts or Windows-based Guest Operating
Systems. 

Note that systems that have VMCI disabled are also affected by this
issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion 4.1.4 / 5.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "MacOSX/Fusion/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Fusion/Version");
path = get_kb_item_or_exit("MacOSX/Fusion/Path");

fixed_version = NULL;
if (version =~ '^4\\.1\\.') fixed_version = '4.1.4';
else if (version =~ '^5\\.') fixed_version ='5.0.2';

if (
  !isnull(fixed_version) &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
