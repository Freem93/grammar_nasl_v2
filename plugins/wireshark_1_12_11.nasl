#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90786);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/27 14:13:07 $");

  script_cve_id(
    "CVE-2016-4006",
    "CVE-2016-4078",
    "CVE-2016-4079",
    "CVE-2016-4080",
    "CVE-2016-4081",
    "CVE-2016-4082",
    "CVE-2016-4085"
  );
  script_osvdb_id(
    136225,
    136558,
    137564,
    137565,
    137566,
    137567,
    137573
  );
  script_xref(name:"EDB-ID", value:"39604");
  script_xref(name:"EDB-ID", value:"39644");

  script_name(english:"Wireshark 1.12.x < 1.12.11 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.12.x prior to 1.12.11. It is, therefore, affected by multiple denial
of service vulnerabilities in the following components :

  - GSM CBCH dissector
  - IAX2 dissector
  - IEEE 802.11 dissector
  - NCP dissector
  - PKTC dissector");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.11.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Wireshark";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];
fix = '1.12.11';

# Affected :
#  1.12.x < 1.12.11
if (version =~ '^1\\.12\\.' && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
