#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90795);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/31 14:53:42 $");

  script_cve_id(
    "CVE-2016-1660",
    "CVE-2016-1661",
    "CVE-2016-1662",
    "CVE-2016-1663",
    "CVE-2016-1664",
    "CVE-2016-1665",
    "CVE-2016-1666",
    "CVE-2016-5168"
  );
  script_bugtraq_id(89106);
  script_osvdb_id(
    137739,
    137740,
    137741,
    137742,
    137743,
    137744,
    137762,
    137763,
    151042
  );

  script_name(english:"Google Chrome < 50.0.2661.94 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 50.0.2661.94. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds write error exists in Blink that allows
    a context-dependent attacker to execute arbitrary code.
    (CVE-2016-1660)

  - A flaw exists due to improper validation of
    user-supplied input when handling cross-process frames.
    A context-dependent attacker can exploit this to corrupt
    memory, resulting in the execution of arbitrary code.
    (CVE-2016-1661)

  - A use-after-free error exists in the extensions
    component. A context-dependent attacker can exploit this
    to dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-1662)

  - A use-after-free free error exists in Blink's V8
    bindings. A context-dependent attacker can exploit this
    to dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-1663)

  - An unspecified flaw exists that allows a
    context-dependent attacker to spoof the address bar.
    (CVE-2016-1664)

  - An unspecified flaw exists in V8 that allows a
    context-dependent attacker to disclose sensitive
    information. (CVE-2016-1665)

  - Multiple unspecified vulnerabilities exist that allow a
    a context-dependent attacker to execute arbitrary code.
    (CVE-2016-1666)

  - A same-origin bypass vulnerability exists in Skia in the
    pinToByte() function in effects/SkArithmeticMode.cpp due
    to improper handling of intermediate color values. An
    unauthenticated, remote attacker can exploit this, via
    timing attacks using the SVG 'feComposite' filter, to
    bypass the same-origin policy. (CVE-2016-5168)");
  # http://googlechromereleases.blogspot.com/2016/04/stable-channel-update_28.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?754e2284");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 50.0.2661.94 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/29");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'50.0.2661.94', severity:SECURITY_HOLE);
