#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81207);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2015-0313",
    "CVE-2015-0314",
    "CVE-2015-0315",
    "CVE-2015-0316",
    "CVE-2015-0317",
    "CVE-2015-0318",
    "CVE-2015-0319",
    "CVE-2015-0320",
    "CVE-2015-0321",
    "CVE-2015-0322",
    "CVE-2015-0323",
    "CVE-2015-0324",
    "CVE-2015-0325",
    "CVE-2015-0326",
    "CVE-2015-0327",
    "CVE-2015-0328",
    "CVE-2015-0329",
    "CVE-2015-0330",
    "CVE-2015-0331",
    "CVE-2015-1209",
    "CVE-2015-1210",
    "CVE-2015-1211",
    "CVE-2015-1212"
  );
  script_bugtraq_id(72429, 72497, 72514, 72698);
  script_osvdb_id(
    117853,
    117947,
    117948,
    117949,
    117967,
    117968,
    117969,
    117970,
    117971,
    117972,
    117973,
    117974,
    117975,
    117976,
    117977,
    117978,
    117979,
    117980,
    117981,
    117982,
    117983,
    118279,
    118280,
    118281,
    118282,
    118288,
    118289,
    118597
  );

  script_name(english:"Google Chrome < 40.0.2214.111 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 40.0.2214.111. It is, therefore, affected by the following
vulnerabilities :

  - Several use-after-free errors exist that allow arbitrary
    code execution. (CVE-2015-0313, CVE-2015-0315,
    CVE-2015-0320, CVE-2015-0322)

  - Several memory corruption errors exist that allow
    arbitrary code execution. (CVE-2015-0314,
    CVE-2015-0316, CVE-2015-0318, CVE-2015-0321,
    CVE-2015-0329, CVE-2015-0330)

  - Several type confusion errors exist that allow
    arbitrary code execution. (CVE-2015-0317, CVE-2015-0319)

  - Several heap-based buffer-overflow errors exist that
    allow arbitrary code execution. (CVE-2015-0323,
    CVE-2015-0327)

  - A buffer overflow error exists that allows arbitrary
    code execution. (CVE-2015-0324)

  - Several null pointer dereference errors exist that have
    unspecified impacts. (CVE-2015-0325, CVE-2015-0326,
    CVE-2015-0328).

  - A user-after-free error exists within the processing of
    invalid m3u8 playlists. A remote attacker, with a
    specially crafted m3u8 playlist file, can force a
    dangling pointer to be reused after it has been freed,
    allowing the execution of arbitrary code.
    (CVE-2015-0331)

  - A use-after-free error exists related to the DOM
    component. (CVE-2015-1209)

  - A cross-origin bypass error exists related to the V8
    JavaScript engine bindings. (CVE-2015-1210)

  - A privilege escalation error exists related to service
    workers. (CVE-2015-1211)

  - Various, unspecified errors exist. (CVE-2015-1212)");
  # http://googlechromereleases.blogspot.com/2015/02/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9661eacd");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-047/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 40.0.2214.111 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player PCRE Regex Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'40.0.2214.111', severity:SECURITY_HOLE, xss:TRUE);
