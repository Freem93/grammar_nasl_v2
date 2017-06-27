#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93940);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_osvdb_id(145253, 145254);

  script_name(english:"Wireshark 2.2.x < 2.2.1 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
2.2.x prior to 2.2.1. It is, therefore, affected by multiple denial of
service vulnerabilities :

  - A denial of service vulnerability exists in the
    ncp2222_compile_dfilters() function within file
    epan/dissectors/packet-ncp2222.inc due to improper
    handling of NCP frames. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to crash the process. (VulnDB 145253)

  - A denial of service vulnerability exists in the
    dissect_disconnrequestresponse() function within file
    epan/dissectors/packet-btl2cap.c when handling short
    bluetooth service names. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to crash the process. (VulnDB 145254)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-56.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-57.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/10");

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
fix = '2.2.1';

if(version !~ "^2\.2\.")
  exit(0, "The remote installation of Wireshark is not 2.2.x.");

# Affected :
#  2.2.x < 2.2.1
if (version !~ "^2\.2\.0($|[^0-9])")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
