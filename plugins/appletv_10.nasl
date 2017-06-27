#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93776);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id(
    "CVE-2016-4611",
    "CVE-2016-4658",
    "CVE-2016-4702",
    "CVE-2016-4708",
    "CVE-2016-4712",
    "CVE-2016-4718",
    "CVE-2016-4725",
    "CVE-2016-4726",
    "CVE-2016-4728",
    "CVE-2016-4730",
    "CVE-2016-4733",
    "CVE-2016-4734",
    "CVE-2016-4735",
    "CVE-2016-4737",
    "CVE-2016-4738",
    "CVE-2016-4753",
    "CVE-2016-4759",
    "CVE-2016-4765",
    "CVE-2016-4766",
    "CVE-2016-4767",
    "CVE-2016-4768",
    "CVE-2016-4772",
    "CVE-2016-4773",
    "CVE-2016-4774",
    "CVE-2016-4775",
    "CVE-2016-4776",
    "CVE-2016-4777",
    "CVE-2016-4778",
    "CVE-2016-5131"
  );
  script_bugtraq_id(
    92053,
    93054,
    93057,
    93059,
    93063,
    93064,
    93065,
    93067
  );
  script_osvdb_id(
    141934,
    144527,
    144529,
    144531,
    144532,
    144533,
    144534,
    144537,
    144538,
    144539,
    144546,
    144547,
    144548,
    144549,
    144552,
    144553,
    144555,
    144556,
    144557,
    144558,
    144559,
    144561,
    144562,
    144565,
    144570,
    144576,
    144591,
    144593,
    144598
  );

  script_name(english:"Apple TV < 10 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 10. It is, therefore, affected by multiple vulnerabilities
in the following components :

  - Audio
  - CFNetwork
  - CoreCrypto
  - FontParser
  - IOAcceleratorFamily
  - Kernel
  - libxml2
  - libxslt
  - Security
  - WebKit

Note that only 4th generation models are affected by these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207142");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 10 or later. Note that this update is only
available for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/Model", "AppleTV/URL", "AppleTV/Port");
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

fixed_build = "14T330";
tvos_ver = '10';
gen = 4;

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  fix_tvos_ver   : tvos_ver,
  model          : model,
  gen            : gen,
  port           : port,
  url            : url,
  severity       : SECURITY_HOLE
);
