#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93520);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id("CVE-2016-7079", "CVE-2016-7080");
  script_bugtraq_id(92938);
  script_osvdb_id(144220, 144221);
  script_xref(name:"VMSA", value:"2016-0014");

  script_name(english:"VMware Tools 9.x / 10.x < 10.0.9 Multiple Privilege Escalations (VMSA-2016-0014) (Mac OS X)");
  script_summary(english:"Checks the VMware Tools version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Mac OS X host is
affected by multiple privilege escalation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Mac OS X host is
9.x or 10.x prior to 10.0.9. It is, therefore, affected by multiple
NULL pointer dereference flaws in the graphic acceleration functions
due to improper memory handling. A local attacker can exploit these to
gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0014.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 10.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_vmware_tools_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Tools");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app = "VMware Tools";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fix = '10.0.9';

if (version =~ "^(9|10)\." && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
