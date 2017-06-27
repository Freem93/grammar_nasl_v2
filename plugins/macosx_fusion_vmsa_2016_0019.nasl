#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95286);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/27 20:06:29 $");

  script_cve_id("CVE-2016-7461");
  script_bugtraq_id(94280);
  script_osvdb_id(147086);
  script_xref(name:"VMSA", value:"2016-0019");

  script_name(english:"VMware Fusion 8.x < 8.5.2 Drag-and-Drop Feature Arbitrary Code Execution (VMSA-2016-0019)");
  script_summary(english:"Checks the VMware Fusion version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Mac OS X host is
affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote Mac OS X host is
8.x prior to 8.5.2. It is, therefore, affected by an arbitrary code
execution vulnerability in the drag-and-drop feature due to an
out-of-bounds memory access error. An attacker within the guest can
exploit this to execute arbitrary code on the host system.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0019.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Fusion version 8.5.2 or later. Alternatively,
disable both the drag-and-drop function and the copy-and-paste
function.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");  
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Fusion", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

install = get_single_install(app_name:"VMware Fusion", exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

fix = '';
if (version =~ "^8\.") fix = '8.5.2';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
