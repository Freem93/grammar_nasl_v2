#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91228);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/09/08 20:37:25 $");

  script_cve_id(
    "CVE-2016-1792",
    "CVE-2016-1793",
    "CVE-2016-1794",
    "CVE-2016-1795",
    "CVE-2016-1796",
    "CVE-2016-1797",
    "CVE-2016-1798",
    "CVE-2016-1799",
    "CVE-2016-1801",
    "CVE-2016-1802",
    "CVE-2016-1803",
    "CVE-2016-1804",
    "CVE-2016-1805",
    "CVE-2016-1806",
    "CVE-2016-1807",
    "CVE-2016-1808",
    "CVE-2016-1809",
    "CVE-2016-1810",
    "CVE-2016-1811",
    "CVE-2016-1812",
    "CVE-2016-1813",
    "CVE-2016-1814",
    "CVE-2016-1815",
    "CVE-2016-1816",
    "CVE-2016-1817",
    "CVE-2016-1818",
    "CVE-2016-1819",
    "CVE-2016-1820",
    "CVE-2016-1821",
    "CVE-2016-1822",
    "CVE-2016-1823",
    "CVE-2016-1824",
    "CVE-2016-1825",
    "CVE-2016-1826",
    "CVE-2016-1827",
    "CVE-2016-1828",
    "CVE-2016-1829",
    "CVE-2016-1830",
    "CVE-2016-1831",
    "CVE-2016-1832",
    "CVE-2016-1833",
    "CVE-2016-1834",
    "CVE-2016-1835",
    "CVE-2016-1836",
    "CVE-2016-1837",
    "CVE-2016-1838",
    "CVE-2016-1839",
    "CVE-2016-1840",
    "CVE-2016-1861",
    "CVE-2016-1842",
    "CVE-2016-1843",
    "CVE-2016-1844",
    "CVE-2016-1846",
    "CVE-2016-1848",
    "CVE-2016-1850",
    "CVE-2016-1851",
    "CVE-2016-1853",
    "CVE-2016-3141",
    "CVE-2016-3142",
    "CVE-2016-4070",
    "CVE-2016-4071",
    "CVE-2016-4072",
    "CVE-2016-4073",
    "CVE-2016-4650"
  );
  script_bugtraq_id(
    84271,
    84306,
    85800,
    85801,
    85991,
    85993,
    90692,
    90694,
    90696,
    90697,
    90698,
    90801,
    91353,
    92034
  );
  script_osvdb_id(
    138546,
    138547,
    138548,
    138549,
    138550,
    138551,
    138552,
    138553,
    138554,
    138555,
    138556,
    138557,
    138558,
    138559,
    138560,
    138561,
    138562,
    138563,
    138564,
    138565,
    138566,
    138567,
    138568,
    138569,
    138570,
    138572,
    138573,
    138574,
    138575,
    138584,
    138585,
    138586,
    138587,
    138588,
    138589,
    138590,
    138591,
    138592,
    138593,
    138594,
    138595,
    138596,
    138597,
    138598,
    138599,
    138600,
    138601,
    138602,
    138603,
    138604,
    138605,
    138606,
    138607,
    138608,
    138609,
    138610,
    138611,
    138612,
    138613,
    139637,
    143884
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-05-16-4");

  script_name(english:"Mac OS X 10.11.x < 10.11.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.11.x prior
to 10.11.5. It is, therefore, affected by multiple vulnerabilities in
the following components :

  - AMD
  - apache_mod_php
  - AppleGraphicsControl
  - AppleGraphicsPowerManagement
  - Assistant
  - ATS
  - Audio
  - Captive
  - CFNetwork
  - CommonCrypto
  - CoreCapture
  - CoreStorage
  - Crash
  - Disk
  - Disk
  - Driver
  - Drivers
  - Drivers
  - Graphics
  - Graphics
  - Graphics
  - ImageIO
  - Images
  - Intel
  - IOAcceleratorFamily
  - IOAudioFamily
  - IOFireWireFamily
  - IOHIDFamily
  - Kernel
  - libc
  - libxml2
  - libxslt
  - Lock
  - MapKit
  - Messages
  - Multi-Touch
  - Network
  - NVIDIA
  - OpenGL
  - Proxies
  - QuickTime
  - Reporter
  - SceneKit
  - Screen
  - Tcl
  - Utility

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206567");
  # http://lists.apple.com/archives/security-announce/2016/May/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46de3fda");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X version 10.11.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");

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

fix = "10.11.5";
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
