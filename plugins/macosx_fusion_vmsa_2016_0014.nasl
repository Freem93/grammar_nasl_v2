#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93519);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2016-7079", "CVE-2016-7080");
  script_bugtraq_id(92938);
  script_osvdb_id(144220, 144221);
  script_xref(name:"VMSA", value:"2016-0014");

  script_name(english:"VMware Fusion 8.x < 8.5.0 Multiple Privilege Escalations (VMSA-2016-0014) (Mac OS X)");
  script_summary(english:"Checks the VMware Fusion version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Mac OS X host is
affected by multiple privilege escalation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote Mac OS X host is
8.x prior to 8.5.0. It is, therefore, affected by multiple NULL
pointer dereference flaws in the graphic acceleration functions due to
improper memory handling. A local attacker can exploit these to gain
elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0014.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Fusion version 8.5.0 or later. Note that VMware
Tools on Mac OS X-based guests must also be updated to completely
mitigate these vulnerabilities.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

install = get_single_install(app_name:"VMware Fusion", exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

fix = '8.5.0';

if (version =~ "^8\." && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
