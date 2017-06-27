#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49089);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id(
    "CVE-2010-3246",
    "CVE-2010-3247",
    "CVE-2010-3248",
    "CVE-2010-3249",
    "CVE-2010-3250",
    "CVE-2010-3251",
    "CVE-2010-3252",
    "CVE-2010-3253",
    "CVE-2010-3254",
    "CVE-2010-3255",
    "CVE-2010-3256",
    "CVE-2010-3257",
    "CVE-2010-3258",
    "CVE-2010-3259"
  );
  script_bugtraq_id(42952, 44204, 44206, 44216);
  script_osvdb_id(
    65314,
    67854,
    67855,
    67857,
    67858,
    67859,
    67860,
    67861,
    67862,
    67863,
    67864,
    67865,
    67866,
    67867
  );

  script_name(english:"Google Chrome < 6.0.472.53 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 6.0.472.53.  It therefore is reportedly affected by multiple
vulnerabilities :

  - It is possible to bypass the pop-up blocker with a blank
    frame target . (Issue #34414)

  - It is possible to visually spoof the URL bar with
    homographic sequences. (Issue #37201)

  - Restrictions on setting clipboard content are not strict
    enough. (Issue #41654)

  - A stale pointer exists with SVG filters. (Issue #45659)

  - It may be possible to enumerate installed extensions.
    (Issue #45876)

  - An unspecified vulnerability in WebSockets could lead
    to a browser NULL crash. (Issue #46750, #51846)

  - A use-after-free error exists in the Notifications
    presenter. (Issue #50386)

  - An unspecified memory corruption issue exists in
    Notification permissions. (Issue #50839)

  - Multiple unspecified integer errors exist in WebSockets.
    (Issue #51360, #51739)

  - A memory corruption issue exists with counter nodes.
    (Issue #51653)

  - Chrome may store an excessive amount of autocomplete
    entries. (Issue #51727)

  - A stale pointer exists in focus handling. (Issue #52443)

  - A Sandbox parameter deserialization error exists.
    (Issue #52682)

  - An unspecified cross-origin image theft issue exists.
    (Issue #53001)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?799b5a8f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 6.0.472.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/02");

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
google_chrome_check_version(installs:installs, fix:'6.0.472.53', severity:SECURITY_HOLE);
