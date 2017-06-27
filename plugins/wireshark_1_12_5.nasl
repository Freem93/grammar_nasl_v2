#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83488);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id(
    "CVE-2015-3808",
    "CVE-2015-3809",
    "CVE-2015-3810",
    "CVE-2015-3811",
    "CVE-2015-3812",
    "CVE-2015-3813",
    "CVE-2015-3814",
    "CVE-2015-3815",
    "CVE-2015-3906"
  );
  script_bugtraq_id(
    74628,
    74629,
    74630,
    74631,
    74632,
    74633,
    74635,
    74637,
    74837
  );
  script_osvdb_id(
    119256,
    122088,
    122089,
    122090,
    122091,
    122092,
    122093
  );

  script_name(english:"Wireshark 1.10.x < 1.10.14 / 1.12.x < 1.12.5 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.10.x prior to 1.10.14, or 1.12.x prior to 1.12.5. It is, therefore,
affected by various denial of service vulnerabilities in the following
items :

  - LBMR dissector (CVE-2015-3808, CVE-2015-3809)

  - WebSocket dissector (CVE-2015-3810)

  - WCP dissector (CVE-2015-3811)

  - X11 dissector (CVE-2015-3812)

  - Packet reassembly code (CVE-2015-3813)

  - IEEE 802.11 dissector (CVE-2015-3814)

  - Android Logcat file parser (CVE-2015-3815,
    CVE-2015-3906)

A remote attacker can exploit these vulnerabilities to cause Wireshark
to crash or consume excessive CPU resources, either by injecting a
specially crafted packet onto the wire or by convincing a user to read
a malformed packet trace or PCAP file.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.5.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.10.14 / 1.12.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

fixed_version = FALSE;

# Affected :
#  1.10.x < 1.10.14
#  1.12.x < 1.12.5
if (version =~ "^1\.10\.(\d|1[0-3])($|[^0-9])")
  fixed_version = "1.10.14";
else if (version =~ "^1\.12\.[0-4]($|[^0-9])")
  fixed_version = "1.12.5";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

if (fixed_version)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
