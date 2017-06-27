#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50049);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/12/18 14:26:56 $");

  script_cve_id(
    "CVE-2010-4033",
    "CVE-2010-4034",
    "CVE-2010-4035",
    "CVE-2010-4036",
    "CVE-2010-4037",
    "CVE-2010-4038",
    "CVE-2010-4040",
    "CVE-2010-4042"
  );
  script_bugtraq_id(44241);
  script_osvdb_id(68834, 68835, 68836, 68837, 68838, 68839, 68841, 68843);
  script_xref(name:"Secunia", value:"41888");

  script_name(english:"Google Chrome < 7.0.517.41 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 7.0.517.41.  Such versions are reportedly affected by multiple
vulnerabilities :

  - It is possible to spam profiles via autofill /
    autocomplete.  (Issue #48225, #51727)

  - An unspecified crash exists relating to forms.
    (Issue #48857)

  - A browser crash exists relating to form autofill.
    (Issue #50428)

  - It is possible to spoof the URL on page unload.
    (Issue #51680)

  - It is possible to bypass the pop-up blocker.
    (Issue #53002)

  - A crash on shutdown exists relating to Web Sockets.
    (Issue #53985)

  - A possible memory corruption exists with animated GIF
    files. (Issue #54500)

  - Stale elements exists in the element map.
    (Issue #56451)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?402ad3e1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 7.0.517.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'7.0.517.41', severity:SECURITY_HOLE);
