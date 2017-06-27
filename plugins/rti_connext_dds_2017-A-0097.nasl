#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99476);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/19 19:21:57 $");

  script_xref(name:"IAVA", value:"2017-A-0097");

  script_name(english:"RTI Connext DDS 5.1.1.x < 5.1.1.5 / 5.2.3.x < 5.2.3.17 / 5.2.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the rti_versions.xml base version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Real Time Innovations (RTI) Connext Data Distribution
Service (DDS) installed on the remote Windows host is 5.1.1.x prior to
5.1.1.5 or 5.2.3.x prior to either 5.2.3.17 or 5.2.7. It is,
therefore, affected by multiple vulnerabilities :

  - A heap-based buffer overflow condition exists that
    allows an unauthenticated, remote attacker to execute
    arbitrary code with system privileges.

  - An integer overflow condition exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code with system privileges.

  - A deserialization issue exists due to improper
    validation of user-supplied data. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition and potentially the execution of
    arbitrary code.

  - An out-of-bounds memory buffer issue exists that allows
    an unauthenticated, remote attacker to cause a denial of
    service condition and execute arbitrary code with system
    privileges.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RTI Connext DDS version 5.1.1.5 / 5.2.3.17 / 5.2.7 or
later.

Note that customers with uncommon architectures may need to contact
RTI for a custom patch. RTI is planning a major software release in
June 2017 to address the vulnerabilities on all currently supported
architectures.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:rti:connext_dds");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("rti_connext_dds_win_installed.nbin");
  script_require_keys("installed_sw/RTI Connext DDS", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "RTI Connext DDS";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver     = install['version'];
path    = install['path'];

if (ver =~ "^[0-9]+(\.[0-9])?$") audit(AUDIT_VER_NOT_GRANULAR, app, ver);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# 5.1.1 < 5.1.1.5
# 5.2.3 < 5.2.3.17
# 5.2.7
# All else, contact vendor
if (ver =~ "^5\.1\.1(\.[0-9]+)?$")
  fix = '5.1.1.5';
else if (ver =~ "^5\.2\.3(\.[0-9]+)?$")
  fix = '5.2.3.17';
else
  fix = '5.2.7';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver;

  if (fix == '5.2.7')
    report += '\n  Contact vendor for patch.\n';
  else
    report += '\n  Fixed version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
