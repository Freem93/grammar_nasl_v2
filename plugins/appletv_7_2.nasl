#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82712);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id(
    "CVE-2015-1068",
    "CVE-2015-1069",
    "CVE-2015-1070",
    "CVE-2015-1071",
    "CVE-2015-1072",
    "CVE-2015-1073",
    "CVE-2015-1074",
    "CVE-2015-1076",
    "CVE-2015-1077",
    "CVE-2015-1078",
    "CVE-2015-1079",
    "CVE-2015-1080",
    "CVE-2015-1081",
    "CVE-2015-1082",
    "CVE-2015-1083",
    "CVE-2015-1086",
    "CVE-2015-1092",
    "CVE-2015-1094",
    "CVE-2015-1095",
    "CVE-2015-1096",
    "CVE-2015-1097",
    "CVE-2015-1099",
    "CVE-2015-1100",
    "CVE-2015-1101",
    "CVE-2015-1102",
    "CVE-2015-1103",
    "CVE-2015-1104",
    "CVE-2015-1105",
    "CVE-2015-1110",
    "CVE-2015-1114",
    "CVE-2015-1117",
    "CVE-2015-1118",
    "CVE-2015-1119",
    "CVE-2015-1120",
    "CVE-2015-1121",
    "CVE-2015-1122",
    "CVE-2015-1123",
    "CVE-2015-1124"
  );
  script_bugtraq_id(
    73176,
    73972,
    73981,
    73983,
    73985,
    73986
  );
  script_osvdb_id(
    119675,
    119676,
    119677,
    119678,
    119679,
    119680,
    119681,
    119683,
    119684,
    119685,
    119686,
    119687,
    119688,
    119689,
    119690,
    120402,
    120403,
    120404,
    120405,
    120406,
    120432,
    120435,
    120443,
    120445,
    120446,
    120447,
    120448,
    120449,
    120450,
    120451,
    120452,
    120453,
    120455,
    120456,
    120461,
    120463,
    120467,
    120470
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-04-08-4");

  script_name(english:"Apple TV < 7.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV device is a version prior
to 7.2. It is, therefore, affected by the following vulnerabilities :

  - Multiple memory corruption vulnerabilities exist in
    WebKit due to improperly validated user-supplied input.
    A remote attacker, using a specially crafted website,
    can exploit these to execute arbitrary code.
    (CVE-2015-1068, CVE-2015-1069, CVE-2015-1070,
    CVE-2015-1071, CVE-2015-1072, CVE-2015-1073,
    CVE-2015-1074, CVE-2015-1076, CVE-2015-1077,
    CVE-2015-1078, CVE-2015-1079, CVE-2015-1080,
    CVE-2015-1081, CVE-2015-1082, CVE-2015-1083,
    CVE-2015-1119, CVE-2015-1120, CVE-2015-1121,
    CVE-2015-1122, CVE-2015-1123, CVE-2015-1124)

  - An error exists in the IOKit objects due to improper
    validation of metadata used by an audio driver, which
    allows arbitrary code execution. (CVE-2015-1086)

  - An XML External Entity (XXE) injection vulnerability
    exists in the NSXMLParser due to improper handling of
    XML files, which allows information disclosure.
    (CVE-2015-1092)

  - An error exists in the IOAcceleratorFamily that allows
    the kernel memory layout to be disclosed.
    (CVE-2015-1094)

  - A memory corruption vulnerability exists in the
    IOHIDFamily API that allows arbitrary code execution.
    (CVE-2015-1095)

  - An error exists in the IOHIDFamily due to improper
    bounds checking, which allows the kernel memory layout
    to be disclosed. (CVE-2015-1096)

  - An error exists in the MobileFrameBuffer due to improper
    bounds checking, which allows the kernel memory layout
    to be disclosed. (CVE-2015-1097)

  - A denial of service vulnerability exists in the
    setreuid() system call due to a race condition.
    (CVE-2015-1099)

  - An out-of-bounds memory error exists in the kernel that
    allows a denial of service attack or information
    disclosure. (CVE-2015-1100)

  - A memory corruption vulnerability exists in the kernel
    that allows arbitrary code execution. (CVE-2015-1101)

  - A denial of service vulnerability exists due to a state
    inconsistency in the processing of TCP headers, which
    can only be exploited from an adjacent network.
    (CVE-2015-1102)

  - A vulnerability exists that allows a man-in-the-middle
    attacker to redirect traffic via ICMP redirects.
    (CVE-2015-1103)

  - A security bypass vulnerability exists due to the
    system treating remote IPv6 packets as local packets,
    which allows an attacker to bypass network filters.
    (CVE-2015-1104)

  - A denial of service vulnerability exists due to improper
    processing of TCP out-of-band data, which allows a
    denial of service by a remote attacker. (CVE-2015-1105)

  - An information disclosure vulnerability exists due to
    unique identifiers being sent to remote servers when
    downloading assets for a podcast. (CVE-2015-1110)

  - An information disclosure vulnerability exists in the
    third-party application sandbox that allows hardware
    identifiers to be accessible by other applications.
    (CVE-2015-1114)

  - A privilege escalation vulnerability exists in the
    setreuid() and setregid() system calls due to a failure
    to drop privileges permanently. (CVE-2015-1117)

  - A memory corruption vulnerability exists due to improper
    bounds checking when processing configuration profiles,
    which allows a denial of service attack. (CVE-2015-1118)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204662");
  # http://lists.apple.com/archives/security-announce/2015/Apr/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7d3541a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV 7.2 or later. Note that this update is only
available for 3rd generation and later models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

fixed_build = "12F69";
tvos_ver = '7.2';
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
