#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34197);
  script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2008-6994",
    "CVE-2008-6995",
    "CVE-2008-6997",
    "CVE-2008-6998"
  );
  script_bugtraq_id(30983, 31029, 31038, 31071);
  script_osvdb_id(47908, 48259, 48260, 48261, 48264);

  script_name(english:"Google Chrome < 0.2.149.29 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 0.2.149.29.  Such versions are reportedly affected by several
issues :

  - A buffer overflow involving long filenames that display
    in the 'Save As...' dialog could lead to arbitrary code
    execution (Issue #1414).

  - A buffer overflow in handling of link targets displayed
    in the status area when a user hovers over a link could
    lead to arbitrary code execution (Fix #1797).

  - An out-of-bounds memory read when parsing URLs ending in
    ':%' could cause the application itself to crash (Issue
    #122).

  - The default Downloads directory is set to Desktop, which
    could lead to malicious cluttering of the desktop with
    unwanted downloads and even execution of arbitrary
    programs (Fix #17933).");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=122");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=1414");
  # http://googlechromereleases.blogspot.com/2008/09/beta-release-0214929.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11235881");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 0.2.149.29.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");
  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'0.2.149.29', severity:SECURITY_HOLE);
