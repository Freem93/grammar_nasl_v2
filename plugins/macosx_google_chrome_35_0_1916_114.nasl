#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74123);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/03 17:40:03 $");

  script_cve_id(
    "CVE-2014-1743",
    "CVE-2014-1744",
    "CVE-2014-1745",
    "CVE-2014-1746",
    "CVE-2014-1747",
    "CVE-2014-1748",
    "CVE-2014-1749",
    "CVE-2014-3152",
    "CVE-2014-3803"
  );
  script_bugtraq_id(67517, 67582);
  script_osvdb_id(
    107139,
    107140,
    107141,
    107142,
    107143,
    107144,
    107145,
    107165,
    107253
  );

  script_name(english:"Google Chrome < 35.0.1916.114 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
a version prior to 35.0.1916.114. It is, therefore, affected by the
following vulnerabilities :

  - Use-after-free errors exist related to 'styles' and
    'SVG' handling. (CVE-2014-1743, CVE-2014-1745)

  - An integer overflow error exists related to audio
    handling. (CVE-2014-1744)

  - An out-of-bounds read error exists related to media
    filters. (CVE-2014-1746)

  - A user-input validation error exists related to
    handling local MHTML files. (CVE-2014-1747)

  - An unspecified error exists related to the scrollbar
    that could allow UI spoofing. (CVE-2014-1748)

  - Various unspecified errors. (CVE-2014-1749)

  - An integer underflow error exists related to the V8
    JavaScript engine. (CVE-2014-3152)

  - An error exists related to the 'Blink' 'SpeechInput'
    feature that could allow click-jacking and information
    disclosure. (CVE-2014-3803)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2014/05/stable-channel-update_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2da726ba");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 35.0.1916.114 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'35.0.1916.114', severity:SECURITY_WARNING, xss:TRUE);
