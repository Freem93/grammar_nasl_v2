#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96877);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/01 15:04:45 $");

  script_cve_id(
    "CVE-2016-8687",
    "CVE-2017-2350",
    "CVE-2017-2354",
    "CVE-2017-2355",
    "CVE-2017-2356",
    "CVE-2017-2360",
    "CVE-2017-2362",
    "CVE-2017-2363",
    "CVE-2017-2365",
    "CVE-2017-2369",
    "CVE-2017-2370",
    "CVE-2017-2373"
  );
  script_bugtraq_id(
    93781,
    95727,
    95728,
    95729,
    95731,
    95736
  );
  script_osvdb_id(
    144365,
    150763,
    150764,
    150765,
    150766,
    150767,
    150768,
    150769,
    150770,
    150771,
    150773,
    150776
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-01-23-4");

  script_name(english:"Apple TV < 10.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 10.1.1. It is, therefore, affected by multiple
vulnerabilities :

  - A stack-based buffer overflow condition exists in
    libarchive in the bsdtar_expand_char() function within
    file util.c due to improper validation of certain
    unspecified input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted archive, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-8687)

  - A prototype access flaw exists in WebKit when handling
    exceptions. An unauthenticated, remote attacker can
    exploit this, via specially crafted web content, to
    disclose cross-origin data. (CVE-2017-2350)

  - A type confusion error exists in WebKit when handling
    SearchInputType objects due to improper validation of
    certain unspecified input. An unauthenticated, remote
    attacker can exploit this, via specially crafted web
    content, to execute arbitrary code. (CVE-2017-2354)

  - An unspecified memory initialization flaw exists in
    WebKit that allows an unauthenticated, remote attacker
    to execute arbitrary code via specially crafted web
    content. (CVE-2017-2355)

  - Multiple memory corruption issues exist in WebKit due to
    improper validation of certain unspecified input. An
    unauthenticated, remote attacker can exploit these, via
    specially crafted web content, to execute arbitrary
    code. (CVE-2017-2356, CVE-2017-2362, CVE-2017-2369,
    CVE-2017-2373)

  - A use-after-free error exists in the host_self_trap mach
    trap. A local attacker can exploit this, via a specially
    crafted application, to dereference already freed memory
    and thereby execute arbitrary code with kernel
    privileges. (CVE-2017-2360)

  - A flaw exists in WebKit when handling page loading due
    to improper validation of certain unspecified input.
    An unauthenticated, remote attacker can exploit this,
    via specially crafted web content, to disclose
    cross-origin data. (CVE-2017-2363)

  - A flaw exists in WebKit when handling variables due
    to improper validation of certain unspecified input.
    An unauthenticated, remote attacker can exploit this,
    via specially crafted web content, to disclose
    cross-origin data. (CVE-2017-2365)

  - A heap buffer overflow condition exists in the
    mach_voucher_extract_attr_recipe_trap() function due to
    improper validation of certain unspecified input. A
    local attacker can exploit this, via a specially
    crafted application, to cause a denial of service
    condition or the execution of arbitrary code with
    kernel privileges. (CVE-2017-2370)

Note that only 4th generation models are affected by these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207485");
  # https://lists.apple.com/archives/security-announce/2017/Jan/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1c5d4b2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 10.1.1 or later. Note that this update is
only available for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

fixed_build = "14U712a";
tvos_ver = '10.1.1';
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
