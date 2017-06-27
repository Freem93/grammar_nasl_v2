#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69139);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id(
    "CVE-2013-2881",
    "CVE-2013-2882",
    "CVE-2013-2883",
    "CVE-2013-2884",
    "CVE-2013-2885",
    "CVE-2013-2886"
  );
  script_bugtraq_id(61547, 61548, 61549, 61550, 61551, 61552);
  script_osvdb_id(
    94816,
    95831,
    95832,
    95833,
    95834,
    95835,
    95836,
    95837,
    95838,
    95839,
    103155
  );

  script_name(english:"Google Chrome < 28.0.1500.95 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 28.0.1500.95.  It is, therefore, affected by multiple
vulnerabilities :

  - A cross-origin restriction bypass error exists
    related to HTML frames. (CVE-2013-2881)

  - A type-confusion error exists in the V8 JavaScript
    engine. (CVE-2013-2882)

  - Use-after-free errors exist related to
    MutationObserver, DOM and input handling.
    (CVE-2013-2883, CVE-2013-2884, CVE-2013-2885)

  - Unspecified errors exist with no further details.
    (CVE-2013-2886)");
  # http://googlechromereleases.blogspot.com/2013/07/stable-channel-update_30.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e3b4d3a");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 28.0.1500.95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'28.0.1500.95', severity:SECURITY_WARNING, xss:TRUE);
