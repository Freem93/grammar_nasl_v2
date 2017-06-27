#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90315);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id(
    "CVE-2012-6685",
    "CVE-2014-0191",
    "CVE-2014-3660",
    "CVE-2015-3730",
    "CVE-2015-3731",
    "CVE-2015-3732",
    "CVE-2015-3733",
    "CVE-2015-3734",
    "CVE-2015-3735",
    "CVE-2015-3736",
    "CVE-2015-3737",
    "CVE-2015-3738",
    "CVE-2015-3739",
    "CVE-2015-3740",
    "CVE-2015-3741",
    "CVE-2015-3742",
    "CVE-2015-3743",
    "CVE-2015-3744",
    "CVE-2015-3745",
    "CVE-2015-3746",
    "CVE-2015-3747",
    "CVE-2015-3748",
    "CVE-2015-3749",
    "CVE-2015-3750",
    "CVE-2015-3751",
    "CVE-2015-3752",
    "CVE-2015-3753",
    "CVE-2015-3759",
    "CVE-2015-3766",
    "CVE-2015-3768",
    "CVE-2015-3776",
    "CVE-2015-3778",
    "CVE-2015-3782",
    "CVE-2015-3784",
    "CVE-2015-3793",
    "CVE-2015-3795",
    "CVE-2015-3796",
    "CVE-2015-3797",
    "CVE-2015-3798",
    "CVE-2015-3800",
    "CVE-2015-3802",
    "CVE-2015-3803",
    "CVE-2015-3804",
    "CVE-2015-3805",
    "CVE-2015-3806",
    "CVE-2015-3807",
    "CVE-2015-5749",
    "CVE-2015-5755",
    "CVE-2015-5756",
    "CVE-2015-5757",
    "CVE-2015-5758",
    "CVE-2015-5761",
    "CVE-2015-5773",
    "CVE-2015-5774",
    "CVE-2015-5775",
    "CVE-2015-5776",
    "CVE-2015-5777",
    "CVE-2015-5778",
    "CVE-2015-5781",
    "CVE-2015-5782",
    "CVE-2015-7995"
  );
  script_bugtraq_id(
    67233,
    70644,
    76337,
    76338,
    76341,
    76343,
    77325
  );
  script_osvdb_id(
    90946,
    106710,
    113389,
    126105,
    126106,
    126107,
    126108,
    126109,
    126110,
    126111,
    126112,
    126113,
    126114,
    126115,
    126116,
    126117,
    126118,
    126119,
    126120,
    126121,
    126122,
    126123,
    126124,
    126125,
    126126,
    126127,
    126128,
    126195,
    126196,
    126197,
    126198,
    126199,
    126200,
    126204,
    126206,
    126207,
    126208,
    126209,
    126210,
    126211,
    126219,
    126220,
    126221,
    126224,
    126225,
    126226,
    126227,
    126228,
    126230,
    126231,
    126232,
    126233,
    126234,
    126235,
    126236,
    126239,
    126240,
    126264,
    126265,
    126269,
    126901
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-02-25-1");

  script_name(english:"Apple TV < 7.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV device is a version prior
to 7.2.1. It is, therefore, affected by multiple vulnerabilities in
the following components :

  - bootp
  - CFPreferences
  - CloudKit
  - Code Signing
  - CoreMedia Playback
  - CoreText
  - DiskImages
  - FontParser
  - ImageIO
  - IOHIDFamily
  - IOKit
  - Kernel
  - Libc
  - Libinfo
  - libpthread
  - libxml2
  - libxpc
  - libxslt
  - Location Framework
  - Office Viewer
  - QL Office
  - Sandbox_profiles
  - WebKit");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205795");
  # https://lists.apple.com/archives/security-announce/2016/Feb/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d959a1e0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 7.2.1 or later. Note that this update is
only available for 3rd generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");


  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include("audit.inc");
include("appletv_func.inc");

url = get_kb_item('AppleTV/URL');
if (empty_or_null(url)) exit(0, 'Cannot determine Apple TV URL.');
port = get_kb_item('AppleTV/Port');
if (empty_or_null(port)) exit(0, 'Cannot determine Apple TV port.');

build = get_kb_item('AppleTV/Version');
if (empty_or_null(build)) audit(AUDIT_UNKNOWN_DEVICE_VER, 'Apple TV');

model = get_kb_item('AppleTV/Model');
if (empty_or_null(model)) exit(0, 'Cannot determine Apple TV model.');

fixed_build = "12H523";
tvos_ver = '7.2.1';
gen = 3;

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  model          : model,
  gen            : gen,
  fix_tvos_ver   : tvos_ver,
  port           : port,
  url            : url,
  severity       : SECURITY_HOLE
);
