#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73307);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/02 20:51:58 $");

  script_cve_id("CVE-2007-0120");
  script_bugtraq_id(21898);
  script_osvdb_id(37580);
  script_xref(name:"EDB-ID", value:"3078");

  script_name(english:"Acunetix Web Vulnerability Scanner 4 < 4.0.20060717 Denial of Service");
  script_summary(english:"Checks version of WVS.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running Acunetix Web Vulnerability Scanner
4 prior to 4.0.20060717. It is, therefore affected by a denial of
service vulnerability. An attacker could potentially exploit this
vulnerability by sending multiple HTTP requests containing invalid
'Content-Length' values to cause an application crash.");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.0.20060717 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:acunetix:web_vulnerability_scanner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("acunetix_wvs_installed.nbin");
  script_require_keys("SMB/AcunetixWVS/4/Path", "SMB/AcunetixWVS/4/Version");
  script_require_ports("SMB/transport", 139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Acunetix Web Vulnerability Scanner";
path = get_kb_item_or_exit("SMB/AcunetixWVS/4/Path");
version = get_kb_item_or_exit("SMB/AcunetixWVS/4/Version");
fix = "4.0.20060717";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path         : ' + path +
      '\n  Version      : ' + version +
      '\n  Fixed Version: ' + fix +
      '\n';
    security_note(extra:report, port:port);
  }
  else security_note(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
