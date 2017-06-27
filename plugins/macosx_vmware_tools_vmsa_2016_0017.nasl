#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94339);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id("CVE-2016-5328");
  script_bugtraq_id(93886);
  script_osvdb_id(146346);
  script_xref(name:"VMSA", value:"2016-0017");
  script_xref(name:"IAVB", value:"2016-B-0156");

  script_name(english:"VMware Tools 9.x / 10.x < 10.1.0 Kernel Memory Address Disclosure (VMSA-2016-0017) (Mac OS X)");
  script_summary(english:"Checks the VMware Tools version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS
X host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote macOS or Mac OS X
host is 9.x or 10.x prior to 10.1.0. It is, therefore, affected by an
information disclosure vulnerability in the System Integrity
Protection (SIP) feature. A local attacker can exploit this issue
to obtain kernel memory addresses and thereby bypass the kASLR
protection mechanism.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0017.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 10.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_vmware_tools_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "installed_sw/VMware Tools", "Settings/ParanoidReport");

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

# Exploitation requires that System Integrity Protection (SIP) is enabled.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '10.1.0';

if (version =~ "^(9|10)\." && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
