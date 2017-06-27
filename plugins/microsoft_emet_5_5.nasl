#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88955);
  script_version("$Revision: 1.2 $");
  script_xref(name:"IAVA", value:"2016-A-0054");
  script_cvs_date("$Date: 2016/02/29 01:27:34 $");

  script_name(english:"Microsoft EMET < 5.5 Security Bypass Vulnerability");
  script_summary(english:"Checks the Microsoft EMET version.");

  script_set_attribute(attribute:"synopsis", value:
"A toolkit for mitigating security vulnerabilities is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Enhanced Mitigation Experience Toolkit (EMET)
installed on the remote host is prior to 5.5. It is, therefore,
affected by a vulnerability that allows a remote attacker to disable
EMET, bypass its protection, and take control of the affected system.");
  #https://www.us-cert.gov/ncas/current-activity/2016/02/23/Microsoft-Releases-Update-EMET
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31839e8e");
  #https://www.fireeye.com/blog/threat-research/2016/02/using_emet_to_disabl.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28c790ab");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft EMET version 5.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:enhanced_mitigation_experience_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("microsoft_emet_installed.nasl");
  script_require_keys("SMB/Microsoft/EMET/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

path    = get_kb_item_or_exit("SMB/Microsoft/EMET/Path");
version = get_kb_item_or_exit("SMB/Microsoft/EMET/Version");

if (
  ver_compare(ver:version, fix:'5.5', strict:FALSE) < 0
)
{
  port = kb_smb_transport();
  if (!port) port = 445;

  report =
    '\n' +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.5' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);

}
else audit(AUDIT_INST_PATH_NOT_VULN, "EMET", version, path);

