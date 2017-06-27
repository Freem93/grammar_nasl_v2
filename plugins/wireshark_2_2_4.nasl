#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96765);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/10 16:05:36 $");

  script_osvdb_id(150784, 150785);

  script_name(english:"Wireshark 2.0.x < 2.0.10 / 2.2.x < 2.2.4 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 2.0.x
prior to 2.0.10 or 2.2.x prior to 2.2.4. It is, therefore, affected by
multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists when handling
    DHCPv6 packets due to an integer overflow condition in
    file epan/dissectors/packet-dhcpv6.c. An
    unauthenticated, remote attacker can exploit this to
    cause the program to enter a large loop that consumes
    excessive CPU resources. (VulnDB 150784)

  - A denial of service vulnerability exists in the
    asterix_fspec_len() function within file
    epan/dissectors/packet-asterix.c due to an infinite loop
    flaw that is triggered because certain input is
    improperly validated. An unauthenticated, remote
    attacker can exploit this to consume excessive CPU
    resources. (VulnDB 150785)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-01.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-02.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.10 / 2.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
fix = NULL;
min = NULL;
flag = 0;

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (version =~ "^2\.0\.")
{
  fix = "2.0.10";
  min = "2.0.0";
  flag++;
}

if (version =~ "^2\.2\.")
{
  fix = "2.2.4";
  min = "2.2.0";
  flag++;
}

if (flag && ver_compare(ver:version, fix:fix, minver:min, strict:FALSE) <  0 )
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else
{
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
}
