#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90096);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/07/13 14:38:01 $");

  script_cve_id(
    "CVE-2014-9495",
    "CVE-2015-0973",
    "CVE-2015-1819",
    "CVE-2015-3195",
    "CVE-2015-5312",
    "CVE-2015-7499",
    "CVE-2015-7500",
    "CVE-2015-7551",
    "CVE-2015-7942",
    "CVE-2015-8035",
    "CVE-2015-8126",
    "CVE-2015-8242",
    "CVE-2015-8472",
    "CVE-2015-8659",
    "CVE-2016-0777",
    "CVE-2016-0778",
    "CVE-2016-0801",
    "CVE-2016-0802",
    "CVE-2016-1732",
    "CVE-2016-1733",
    "CVE-2016-1734",
    "CVE-2016-1735",
    "CVE-2016-1736",
    "CVE-2016-1737",
    "CVE-2016-1738",
    "CVE-2016-1740",
    "CVE-2016-1741",
    "CVE-2016-1743",
    "CVE-2016-1744",
    "CVE-2016-1745",
    "CVE-2016-1746",
    "CVE-2016-1747",
    "CVE-2016-1748",
    "CVE-2016-1749",
    "CVE-2016-1750",
    "CVE-2016-1752",
    "CVE-2016-1753",
    "CVE-2016-1754",
    "CVE-2016-1755",
    "CVE-2016-1756",
    "CVE-2016-1757",
    "CVE-2016-1758",
    "CVE-2016-1759",
    "CVE-2016-1761",
    "CVE-2016-1762",
    "CVE-2016-1764",
    "CVE-2016-1767",
    "CVE-2016-1768",
    "CVE-2016-1769",
    "CVE-2016-1770",
    "CVE-2016-1773",
    "CVE-2016-1775",
    "CVE-2016-1788",
    "CVE-2016-1950"
  );
  script_bugtraq_id(
    71820,
    71994,
    75570,
    77390,
    77568,
    77681,
    78624,
    78626,
    79507,
    79509,
    79536,
    79562,
    80438,
    80695,
    80698
  );
  script_osvdb_id(
    116195,
    116943,
    120600,
    121175,
    129696,
    130175,
    130292,
    130536,
    130538,
    130539,
    131039,
    131943,
    132239,
    132883,
    132884,
    133867,
    133868,
    135603,
    136099,
    136101,
    136102,
    136103,
    136104,
    136105,
    136106,
    136108,
    136109,
    136110,
    136111,
    136112,
    136113,
    136114,
    136117,
    136132,
    136133,
    136134,
    136135,
    136136,
    136137,
    136138,
    136139,
    136140,
    136141,
    136142,
    136143,
    136144,
    136145,
    136146,
    136147,
    136148,
    136149,
    136150,
    136151
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-03-21-5");

  script_name(english:"Mac OS X 10.11.x < 10.11.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.11.x prior
to 10.11.4. It is, therefore, affected by multiple vulnerabilities in
the following components :

  - apache_mod_php
  - AppleRAID
  - AppleUSBNetworking
  - Bluetooth
  - Carbon
  - dyld
  - FontParser
  - HTTPProtocol
  - Intel Graphics Driver
  - IOFireWireFamily
  - IOGraphics
  - IOHIDFamily
  - IOUSBFamily
  - Kernel
  - libxml2
  - Messages
  - NVIDIA Graphics Drivers
  - OpenSSH
  - OpenSSL
  - Python
  - QuickTime
  - Reminders
  - Ruby
  - Security
  - Tcl
  - TrueTypeScaler
  - Wi-Fi

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206167");
  # http://lists.apple.com/archives/security-announce/2016/Mar/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c87f79a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X version 10.11.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os)
    audit(AUDIT_OS_NOT, "Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70)
    exit(1, "Cannot determine the host's OS with sufficient confidence.");
}
if (!os)
  audit(AUDIT_OS_NOT, "Mac OS X");

match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];

if (
  version !~ "^10\.11([^0-9]|$)"
) audit(AUDIT_OS_NOT, "Mac OS X 10.11 or later", "Mac OS X "+version);

fix = "10.11.4";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  items = make_array("Installed version", version,
                     "Fixed version", fix
                    );
  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
  exit(0);

 }
else
  audit(AUDIT_INST_VER_NOT_VULN, "Mac OS X", version);
