#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88418);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id(
    "CVE-2015-7995",
    "CVE-2016-1717",
    "CVE-2016-1719",
    "CVE-2016-1720",
    "CVE-2016-1721",
    "CVE-2016-1722",
    "CVE-2016-1724",
    "CVE-2016-1727"
  );
  script_bugtraq_id(77325);
  script_osvdb_id(
    126901,
    133138,
    133139,
    133140,
    133141,
    133142,
    133144,
    133147
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-01-25-1");

  script_name(english:"Apple TV < 9.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV device is a version prior
to 9.1.1. It is, therefore, affected by the following
vulnerabilities :

  - A type confusion error exists in the bundled libxslt
    library due to improper handling of invalid values. An
    attacker can exploit this to crash the application,
    resulting in a denial of service condition.
    (CVE-2015-7995)

  - A memory corruption issue exists due to improper
    validation of user-supplied input when handling disk
    images. A local attacker can exploit this to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-1717)

  - A use-after-free error exists in the IOHIDFamily API
    due to improper validation of user-supplied input. A
    local attacker can exploit this to dereference already
    freed memory, resulting in a denial of service condition
    or the execution of arbitrary code. (CVE-2016-1719)

  - A memory corruption issue exists in IOKit due to
    improper validation of user-supplied input. A local
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-1720)

  - A memory corruption issue exists in the Kernel due to
    improper validation of user-supplied input. A local
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-1721)

  - An overflow condition exists in the
    add_lockdown_session() function due to improper
    validation of user-supplied input. A local attacker can
    exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-1722)

  - Multiple memory corruption issues exist in WebKit due to
    improper validation of user-supplied input. A remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-1724, CVE-2016-1727)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205729");
  # https://lists.apple.com/archives/security-announce/2016/Jan/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbf27a14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 9.1.1 or later. Note that this update is
only available for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/27");

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

fixed_build = "13U717";
tvos_ver = '9.1.1';
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
