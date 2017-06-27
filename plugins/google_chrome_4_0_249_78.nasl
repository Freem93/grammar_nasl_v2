#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44317);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:19:26 $");

  script_cve_id(
    'CVE-2010-0650',
    'CVE-2010-0651',
    'CVE-2010-0655',
    'CVE-2010-0656',
    'CVE-2010-0657',
    'CVE-2010-0658',
    'CVE-2010-0659',
    'CVE-2010-0660',
    'CVE-2010-0661',
    'CVE-2010-0662',
    'CVE-2010-0663',
    'CVE-2010-0664'
  );
  script_bugtraq_id(37948,38372,38373,38374,38375);
  script_osvdb_id(
    62305,
    62306,
    62307,
    62308,
    62309,
    62310,
    62311,
    62312,
    62313,
    62314,
    62461,
    62462,
    62463
  );
  script_xref(name:"Secunia", value:"37769");

  script_name(english:"Google Chrome < 4.0.249.78 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Google Chrome installed on the remote host is earlier
than 4.0.249.78.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A pop-up blocker bypass. (Issue #3275)

  - Cross-domain theft due to CSS design error.
    (Issue #9877)

  - Browser memory error with stale pop-up block menu.
    (Issue #12523)

  - An unspecified error allows XMLHttpRequests to
    directories. (Issue #20450)

  - An unspecified error exists related to escaping
    characters in shortcuts. (Issue #23693)

  - Renderer memory errors exist when drawing on canvases.
    (Issue #8864, #24701, #24646)

  - An image decoding memory error. (Issue #28566)

  - An unspecified error exists that could result in failure
    to strip 'Referer'. (Issue #29920)

  - An unspecified cross-domain access error. (Issue #30666)

  - An unspecified bitmap deserialization error.
    (Issue #31307)

  - An unspecified browser crash related to nested URLs.
    (Issue #31517)"
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-65/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f2b858d");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 4.0.249.78 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 189, 200, 264, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'4.0.249.78', severity:SECURITY_HOLE);
