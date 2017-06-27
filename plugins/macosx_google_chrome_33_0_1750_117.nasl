#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72617);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/03 03:33:27 $");

  script_cve_id(
    "CVE-2013-6653",
    "CVE-2013-6654",
    "CVE-2013-6655",
    "CVE-2013-6656",
    "CVE-2013-6657",
    "CVE-2013-6658",
    "CVE-2013-6659",
    "CVE-2013-6660",
    "CVE-2013-6661"
  );
  script_bugtraq_id(65699);
  script_osvdb_id(
    103523,
    103524,
    103525,
    103526,
    103527,
    103528,
    103529,
    103530,
    103531,
    103532,
    103607,
    103608,
    103609,
    103610,
    103611,
    103612,
    103613,
    103614,
    103615,
    103616,
    103617,
    103618,
    103619,
    103620,
    103629,
    103632
  );

  script_name(english:"Google Chrome < 33.0.1750.117 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is a
version prior to 33.0.1750.117.  It is, therefore, affected by the
following vulnerabilities :

  - Use-after-free errors exist related to handling
    web components and layout. (CVE-2013-6653,
    CVE-2013-6655, CVE-2013-6658)

  - A casting error exists related to SVG processing.
    (CVE-2013-6654)

  - Errors exist related to the XSS auditor that could lead
    to disclosure of information. (CVE-2013-6656,
    CVE-2013-6657)

  - An error exists related to certificate validation and
    TLS handshake processing. (CVE-2013-6659)

  - An error exists related to drag and drop handling that
    could lead to disclosure of information. (CVE-2013-6660)

  - Various unspecified errors exist having unspecified
    impacts. (CVE-2013-6661)");
  # http://googlechromereleases.blogspot.com/2014/02/stable-channel-update_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43898a73");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 33.0.1750.117 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'33.0.1750.117', severity:SECURITY_WARNING);
