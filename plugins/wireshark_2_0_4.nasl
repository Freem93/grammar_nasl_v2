#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91821);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/07/06 14:12:42 $");

  script_cve_id(
    "CVE-2016-5350",
    "CVE-2016-5351",
    "CVE-2016-5352",
    "CVE-2016-5353",
    "CVE-2016-5354",
    "CVE-2016-5355",
    "CVE-2016-5356",
    "CVE-2016-5357",
    "CVE-2016-5358"
  );
  script_osvdb_id(
    138537,
    139587,
    139588,
    139589,
    139590,
    139591,
    139592,
    139593,
    139594
  );

  script_name(english:"Wireshark 2.0.x < 2.0.4 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 
2.0.x prior to 2.0.4. It is, therefore, affected by multiple denial 
of service vulnerabilities :

  - An infinite loop exists in the SPOOLs dissector. A
    remote attacker, via a specially crafted packet or trace
    file, can exploit this to exhaust CPU resources,
    resulting in a denial of service condition.
    (CVE-2016-5350)

  - A flaw exists in the IEEE 802.11 dissector that is
    triggered when handling a malformed packet or trace
    file. A remote attacker can exploit this to cause a
    denial of service condition. (CVE-2016-5351)

  - An out-of-bounds read error exists in the
    AirPDcapDecryptWPABroadcastKey() function in airpdcap.c
    that allows a remote attacker to disclose memory
    contents or cause a denial of service condition.
    (CVE-2016-5352)

  - A flaw exists in the UMTS FP dissector that is triggered
    when handling a malformed packet or trace file. A remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-5353)

  - A flaw exists in multiple USB dissectors that is
    triggered when a handling malformed packet or trace
    file. A remote attacker can exploit this to cause a
    denial of service condition. (CVE-2016-5354)

  - A flaw exists in the Toshiba file parser that is
    triggered when handling a malformed packet trace file. A
    remote attacker can exploit this, by convincing a user
    to open a specially crafted packet trace file, to cause
    a denial of service condition. (CVE-2016-5355)

  - A flaw exists in the CoSine file parser that is
    triggered when handling a malformed packet trace file. A
    remote attacker can exploit this to cause a denial of
    service condition. (CVE-2016-5356)

  - A flaw exists in the NetScreen file parser that is
    triggered when handling a malformed packet trace file. A
    remote attacker can exploit this to cause a denial of
    service condition. (CVE-2016-5357)

  - A flaw exists in the Ethernet dissector that is
    triggered when handling a malformed packet or trace
    file. A remote attacker can exploit this to cause a
    denial of service condition. (CVE-2016-5358)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-29.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-30.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-31.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-32.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-33.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-34.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-35.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-36.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2016-37.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

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

if(version !~ "^2\.0\.") 
  exit(0, "The remote installation of Wireshark is not 2.0.x.");

# Affected :
#  2.0.x < 2.0.4
if (version !~ "^2\.0\.[0-3]($|[^0-9])")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 2.0.4' +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
