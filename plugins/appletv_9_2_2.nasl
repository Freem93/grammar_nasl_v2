#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92494);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id(
    "CVE-2016-1684",
    "CVE-2016-1836",
    "CVE-2016-1863",
    "CVE-2016-1865",
    "CVE-2016-4447",
    "CVE-2016-4448",
    "CVE-2016-4449",
    "CVE-2016-4483",
    "CVE-2016-4582",
    "CVE-2016-4583",
    "CVE-2016-4584",
    "CVE-2016-4585",
    "CVE-2016-4586",
    "CVE-2016-4587",
    "CVE-2016-4588",
    "CVE-2016-4589",
    "CVE-2016-4591",
    "CVE-2016-4592",
    "CVE-2016-4594",
    "CVE-2016-4607",
    "CVE-2016-4608",
    "CVE-2016-4609",
    "CVE-2016-4610",
    "CVE-2016-4612",
    "CVE-2016-4614",
    "CVE-2016-4615",
    "CVE-2016-4616",
    "CVE-2016-4619",
    "CVE-2016-4622",
    "CVE-2016-4623",
    "CVE-2016-4624",
    "CVE-2016-4626",
    "CVE-2016-4627",
    "CVE-2016-4631",
    "CVE-2016-4632",
    "CVE-2016-4637",
    "CVE-2016-4642",
    "CVE-2016-4643",
    "CVE-2016-4644",
    "CVE-2016-4653"
  );
  script_bugtraq_id(
    90013,
    90856,
    90864,
    90865,
    90876,
    91358,
    91826,
    91827,
    91828,
    91830,
    91831,
    91834
  );
  script_osvdb_id(
    137965,
    138568,
    138926,
    138928,
    138966,
    139032,
    140212,
    141602,
    141607,
    141608,
    141610,
    141612,
    141613,
    141614,
    141615,
    141617,
    141618,
    141619,
    141620,
    141621,
    141622,
    141623,
    141624,
    141625,
    141646,
    141653,
    141654,
    141655,
    141656,
    141657,
    141658,
    141659,
    141661,
    141663,
    141664,
    141665,
    141666
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-07-18-4");

  script_name(english:"Apple TV < 9.2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Apple TV device is
prior to 9.2.2. It is, therefore, affected by multiple vulnerabilities
in the following components :

  - CoreGraphics
  - ImageIO
  - IOAcceleratorFamily
  - IOHIDFamily
  - Kernel
  - libxml2
  - libxslt
  - Sandbox Profiles
  - WebKit
  - WebKit Page Loading

Note that only 4th generation models are affected by the
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206905");
  # https://lists.apple.com/archives/security-announce/2016/Jul/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c0647e9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 9.2.2 or later. Note that this update is
only available for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/21");

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

# fix
fixed_build = "13Y825";
tvos_ver = '9.2.2'; # for reporting purposes only
gen = 4;            # apple tv generation

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  fix_tvos_ver   : tvos_ver,
  model          : model,
  gen            : gen,
  port           : port,
  url            : url,
  severity       : SECURITY_HOLE,
  xss            : TRUE
);
