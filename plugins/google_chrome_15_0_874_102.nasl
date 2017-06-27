#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56650);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-2845",
    "CVE-2011-3875",
    "CVE-2011-3876",
    "CVE-2011-3877",
    "CVE-2011-3878",
    "CVE-2011-3879",
    "CVE-2011-3880",
    "CVE-2011-3881",
    "CVE-2011-3882",
    "CVE-2011-3883",
    "CVE-2011-3884",
    "CVE-2011-3885",
    "CVE-2011-3886",
    "CVE-2011-3887",
    "CVE-2011-3888",
    "CVE-2011-3889",
    "CVE-2011-3890",
    "CVE-2011-3891"
  );
  script_bugtraq_id(50360);
  script_osvdb_id(
    76545,
    76546,
    76547,
    76548,
    76549,
    76550,
    76551,
    76552,
    76553,
    76554,
    76555,
    76556,
    76557,
    76558,
    76559,
    76560,
    76561,
    76562,
    90387,
    90388,
    90389,
    90390,
    90446,
    90447,
    90448,
    90449,
    90450
  );

  script_name(english:"Google Chrome < 15.0.874.102 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 15.0.874.102.  It therefore is potentially affected by the
following vulnerabilities :

  - Several URL bar spoofing errors exist related to
    history handling and drag-and-drop of URLs.
    (CVE-2011-2845, CVE-2011-3875)

  - Whitespace is stripped from the end of download
    filenames. (CVE-2011-3876)

  - A cross-site scripting issue exists related to the
    'appcache' internals page. (CVE-2011-3877)

  - A race condition exists related to working process
    initialization. (CVE-2011-3878)

  - An error exists related to redirection to 'chrome
    scheme' URIs. (CVE-2011-3879)

  - Unspecified special characters may be used as
    delimiters in HTTP headers. (CVE-2011-3880)

  - Several cross-origin policy violation issues exist.
    (CVE-2011-3881)

  - Several use-after-free errors exist related to media
    buffer handling, counter handling, stale styles,
    plugins and editing, and video source handling.
    (CVE-2011-3882, CVE-2011-3883, CVE-2011-3885,
    CVE-2011-3888, CVE-2011-3890)

  - Timing issues exist related to DOM traversal.
    (CVE-2011-3884)

  - An out-of-bounds write error exists in the V8
    JavaScript engine. (CVE-2011-3886)

  - Cookie theft is possible via JavaScript URIs.
    (CVE-2011-3887)

  - A heap overflow issue exists related to Web Audio.
    (CVE-2011-3889)

  - Functions internal to the V8 JavaScript engine are
    exposed. (CVE-2011-3891)");
  # http://googlechromereleases.blogspot.com/2011/10/chrome-stable-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?614d8eb8");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 15.0.874.102 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'15.0.874.102', xss:TRUE, severity:SECURITY_HOLE);
