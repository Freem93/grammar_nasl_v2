#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(71230);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/19 00:18:13 $");

  script_cve_id("CVE-2013-3519");
  script_bugtraq_id(64075);
  script_osvdb_id(100514);
  script_xref(name:"VMSA", value:"2013-0014");

  script_name(english:"VMware Fusion 5.x < 5.0.4 LGTOSYNC.SYS Privilege Escalation (VMSA-2013-0014)");
  script_summary(english:"Checks version of Fusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion 5.x installed on the remote Mac OS X host
is prior to 5.0.4.  It is, therefore, reportedly affected by a privilege
escalation vulnerability in the LGTOSYNC.SYS driver on 32-bit Guest
Operating Systems running Windows XP. 

Note that by exploiting this issue, a local attacker could elevate his
privileges only on the Guest Operating System and not on the host.");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion 5.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/05");

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

fixed_version = '5.0.4';
if (
  version =~ "^5\." &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
