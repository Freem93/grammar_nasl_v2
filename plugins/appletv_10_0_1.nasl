#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94337);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/30 22:32:39 $");

  script_cve_id(
    "CVE-2016-4613",
    "CVE-2016-4660",
    "CVE-2016-4664",
    "CVE-2016-4665",
    "CVE-2016-4666",
    "CVE-2016-4669",
    "CVE-2016-4673",
    "CVE-2016-4675",
    "CVE-2016-4677",
    "CVE-2016-4679",
    "CVE-2016-4680",
    "CVE-2016-4688",
    "CVE-2016-7578",
    "CVE-2016-7579",
    "CVE-2016-7584",
    "CVE-2016-7613"
  );
  script_bugtraq_id(
    93849,
    93851,
    93853,
    93854,
    93856,
    93949,
    94116,
    94571,
    94572
  );
  script_osvdb_id(
    146204,
    146206,
    146207,
    146208,
    146209,
    146210,
    146211,
    146212,
    146213,
    146214,
    146215,
    146224,
    146343,
    146369,
    147944,
    147945
  );

  script_name(english:"Apple TV < 10.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 10.0.1. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in WebKit when handling the location
    attribute that allows an unauthenticated, remote
    attacker to bypass the cross-origin policies and
    disclose sensitive user information. (CVE-2016-4613)

  - An out-of-bounds read error exists in the FontParser
    component when handling specially crafted font files
    that allows an unauthenticated, remote attacker to
    disclose sensitive information. (CVE-2016-4660)

  - An unspecified flaw exists in the Sandbox Profiles
    component that allows a local attacker, via a specially
    crafted application, to disclose the metadata of photo
    directories. (CVE-2016-4664)

  - An unspecified flaw exists in the Sandbox Profiles
    component that allows a local attacker, via a specially
    crafted application, to disclose the metadata of audio
    recordings. (CVE-2016-4665)

  - Multiple memory corruption issues exist in Webkit due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    execute arbitrary code. (CVE-2016-4666, CVE-2016-4677,
    CVE-2016-7578)

  - Multiple unspecified flaws exist in the System Boot
    component, within MIG generated code, due to improper
    validation of input. A local attacker can exploit these
    to terminate the system or execute arbitrary code with
    elevated privileges. (CVE-2016-4669)

  - A memory corruption issue exists in the CoreGraphics
    component when handling specially crafted JPEG files. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-4673)

  - An unspecified logic issue exists in libxpc that allows
    a local attacker to execute arbitrary code with root
    privileges. (CVE-2016-4675)

  - A flaw exists in libarchive due to improper path
    validation when creating temporary files during archive
    extraction. An unauthenticated, remote attacker can
    exploit this, via a symlink attack, to overwrite
    arbitrary files. (CVE-2016-4679)

  - An unspecified flaw exists in the Kernel component due
    to improper sanitization of input. A local attacker can
    exploit this to disclose kernel memory contents.
    (CVE-2016-4680)
  
  - An overflow condition exists in the FontParser component
    due to improper validation when parsing font files. An
    unauthenticated, remote attacker can exploit this to
    cause a buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-4688)

  - A flaw exists in the CFNetwork Proxies component when
    handling proxy credentials that allows a
    man-in-the-middle attacker to disclose sensitive user
    information. (CVE-2016-7579)

  - A flaw exists in the AppleMobileFileIntegrity component
    due to improper validation of code signatures. A local
    attacker can exploit this to have a signed executable
    substitute code with the same team ID. (CVE-2016-7584)

  - Multiple race conditions exist in various IOKit drivers
    related to how they use task struct pointers. A local
    attacker can exploit this to execute arbitrary code with
    kernel-level privileges. (CVE-2016-7613)

Note that only 4th generation models are affected by these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207270");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 10.0.1 or later. Note that this update is
only available for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

fixed_build = "14U71";
tvos_ver = '10.0.1';
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
