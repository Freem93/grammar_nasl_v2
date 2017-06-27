#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99103);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id(
    "CVE-2017-4902",
    "CVE-2017-4903",
    "CVE-2017-4904",
    "CVE-2017-4905"
  );
  script_bugtraq_id(
    97160,
    97163,
    97164,
    97165
  );
  script_osvdb_id(
    154017,
    154021,
    154022,
    154594
  );
  script_xref(name:"VMSA", value:"2017-0006");
  script_xref(name:"IAVA", value:"2017-A-0086");

  script_name(english:"VMware Fusion 8.x < 8.5.6 Multiple Vulnerabilities (VMSA-2017-0006) (macOS)");
  script_summary(english:"Checks the VMware Fusion version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote macOS or Mac OS X
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion installed on the remote macOS or Mac OS X
host is 8.x prior to 8.5.6. It is, therefore, affected by multiple
vulnerabilities :

  - A heap buffer overflow condition exists due to improper
    validation of certain input. An attacker on the guest
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code on the host.
    (CVE-2017-4902)

  - A stack memory initialization flaw exists that allows an
    attacker on the guest to execute arbitrary code on the
    host. (CVE-2017-4903)

  - An unspecified flaw exists in memory initialization that
    allows an attacker on the guest to execute arbitrary
    code on the host. (CVE-2017-4904)

  - An unspecified flaw exists in memory initialization that
    allows the disclosure of sensitive information.
    (CVE-2017-4905)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0006.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Fusion version 8.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
if (version =~ "^8\.") fix = '8.5.6';

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
