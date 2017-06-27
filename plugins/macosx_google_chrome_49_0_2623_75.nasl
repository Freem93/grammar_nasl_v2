#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89686);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2015-8126",
    "CVE-2016-1630",
    "CVE-2016-1631",
    "CVE-2016-1632",
    "CVE-2016-1633",
    "CVE-2016-1634",
    "CVE-2016-1635",
    "CVE-2016-1636",
    "CVE-2016-1637",
    "CVE-2016-1638",
    "CVE-2016-1639",
    "CVE-2016-1640",
    "CVE-2016-1641",
    "CVE-2016-1642",
    "CVE-2016-2843"
  );
  script_osvdb_id(
    130175,
    135241,
    135242,
    135243,
    135244,
    135245,
    135246,
    135247,
    135248,
    135249,
    135250,
    135251,
    135252,
    135287,
    135458,
    135459,
    135460,
    135461,
    135462,
    135463,
    135470,
    135471,
    135619,
    135648
  );
  script_name(english:"Google Chrome < 49.0.2623.75 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 49.0.2623.75. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple overflow conditions exist in the libpng library
    in the png_set_PLTE() and png_get_PLTE() functions due
    to improper handling of bit depths less than eight. A
    remote attacker can exploit this, via a specially
    crafted PNG image, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-8126)

  - An unspecified flaw exists in Blink that allows an
    attacker to bypass the same-origin policy.
    (CVE-2016-1630)

  - An unspecified flaw exists in the Pepper plugin that
    allows an attacker to bypass the same-origin policy.
    (CVE-2016-1631)

  - A bad cast flaw exists in the Extensions component that
    allows an attacker to have an unspecified impact.
    (CVE-2016-1632)

  - Multiple use-after-free errors exist in Blink. A remote
    attacker can exploit these issues to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2016-1633, CVE-2016-1634, CVE-2016-1635)

  - An unspecified flaw exists that allows an attacker to
    bypass SRI validation. (CVE-2016-1636)

  - An unspecified flaw exists that allows an attacker to
    disclose sensitive information. (CVE-2016-1637)

  - An unspecified flaw exists that allows an attacker to
    bypass the webAPI. (CVE-2016-1638)

  - A use-after-free error exists in WebRTC. A remote
    attacker can exploit this issue to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2016-1639)

  - An unspecified origin confusion flaw exists in the
    Extensions UI that allows an attacker to have an
    unspecified impact. (CVE-2016-1640)

  - A use-after-free error exists in Favicon. A remote
    attacker can exploit this issue to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2016-1641)

  - Multiple flaws exist that allow a remote attacker to
    execute arbitrary code. (CVE-2016-1642)

  - Multiple unspecified flaws exist in Google V8 in
    runetime-scopes.cc that allows an attacker to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-2843)");
  # http://googlechromereleases.blogspot.com/2016/03/stable-channel-update.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?c095da5b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 49.0.2623.75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'49.0.2623.75', severity:SECURITY_HOLE);
