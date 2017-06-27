#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66556);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id(
    "CVE-2013-2836",
    "CVE-2013-2837",
    "CVE-2013-2838",
    "CVE-2013-2839",
    "CVE-2013-2840",
    "CVE-2013-2841",
    "CVE-2013-2842",
    "CVE-2013-2843",
    "CVE-2013-2844",
    "CVE-2013-2845",
    "CVE-2013-2846",
    "CVE-2013-2847",
    "CVE-2013-2848",
    "CVE-2013-2849"
  );
  script_bugtraq_id(
    60062,
    60063,
    60064,
    60065,
    60066,
    60067,
    60068,
    60069,
    60070,
    60071,
    60072,
    60073,
    60074,
    60076
  );
  script_osvdb_id(
    91117,
    91504,
    91801,
    91899,
    92675,
    92818,
    93249,
    93567,
    93568,
    93569,
    93570,
    93572,
    93573,
    93574,
    93576,
    93577,
    93578,
    93580,
    93638,
    93643,
    93684,
    93686,
    93689,
    93887,
    93888,
    93889,
    93890,
    93891,
    93892,
    93893,
    93894,
    93895,
    93896,
    93897,
    93898,
    93903,
    93904,
    93905,
    93927,
    93928,
    93929,
    93930,
    93931,
    93932,
    93933,
    93936,
    93937,
    93938,
    93939,
    93941,
    93943,
    93945,
    93983,
    93984,
    93985,
    93986,
    93987,
    93988,
    93989,
    93990,
    93991,
    93992,
    93993,
    93994,
    93995,
    93996,
    93997,
    93998,
    93999,
    94000,
    94001,
    94002,
    94003,
    94004,
    94559
  );

  script_name(english:"Google Chrome < 27.0.1453.93 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 27.0.1453.93 and is, therefore, affected by the following
vulnerabilities :

  - Use-after-free errors exist in SVG, media loader,
    Pepper resource handling, widget handling, speech
    handling, style resolution, media loader, and related to
    race condition with workers.  (CVE-2013-2837,
    CVE-2013-2840, CVE-2013-2841, CVE-2013-2842,
    CVE-2013-2843, CVE-2013-2844, CVE-2013-2846,
    CVE-2013-2847)

  - An out-of-bounds read error exists in v8.
    (CVE-2013-2838)

  - A memory corruption vulnerability exists related to
    a bad casting in clipboard handling.  (CVE-2013-2839)

  - A memory safety issue exists related to Web Audio.
    (CVE-2013-2845)

  - An information disclosure vulnerability exists related
    to XSS Auditor.  (CVE-2013-2848)

  - A cross-site scripting vulnerability exists related to
    drag and drop or copy and paste.  (CVE-2013-2849)");

  # http://googlechromereleases.blogspot.com/2013/05/stable-channel-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef8d3a90");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 27.0.1453.93 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'27.0.1453.93', xss:TRUE, severity:SECURITY_WARNING);
