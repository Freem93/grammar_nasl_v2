#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81790);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id("CVE-2015-1061", "CVE-2015-1062", "CVE-2015-1067");
  script_bugtraq_id(73003, 73004, 73009);
  script_osvdb_id(119322, 119324, 119281);
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-03-09-2");

  script_name(english:"Apple TV < 7.1 Multiple Vulnerabilities (FREAK)");
  script_summary(english:"Checks the version in the banner.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV device is a version prior
to 7.1. It is, therefore, affected by the following vulnerabilities :

  - A type confusion error exists related to 'IOSurface' and
    serialized object handling that allow arbitrary code
    execution. (CVE-2015-1061)

  - An error exists in 'MobileStorageMounter' related to
    developer disk mounting logic and invalid disk image
    folders that allows a malicious application to create
    folders in trusted locations. (CVE-2015-1062)

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-1067)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204426");
  # http://lists.apple.com/archives/security-announce/2015/Mar/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ebd0d41");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV 7.1 or later. Note that this update is only
available for 3rd generation and later models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

fixed_build = "12D508";
tvos_ver = '7.1';
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
