#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48383);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id(
    "CVE-2010-3112",
    "CVE-2010-3113",
    "CVE-2010-3114",
    "CVE-2010-3115",
    "CVE-2010-3116",
    "CVE-2010-3117",
    "CVE-2010-3118",
    "CVE-2010-3119",
    "CVE-2010-3120"
  );
  script_bugtraq_id(42571, 44199, 44200, 44201, 44203);
  script_osvdb_id(
    67458,
    67459,
    67460,
    67461,
    67462,
    67464,
    67465,
    67466,
    67467,
    89663
  );

  script_name(english:"Google Chrome < 5.0.375.127 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 5.0.375.127.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A memory corruption vulnerability exists with the file
    dialog. (Issue #45400)

  - A memory corruption vulnerability exists when
    processing SVG files. (Issue #49596)

  - A vulnerability exists due to a bad cast with text
    editing. (Issue #49628)

  - A vulnerability exists that possibly allows address
    bar spoofing via a history bug. (Issue #49964)

  - A memory corruption vulnerability exists in MIME type
    handling. (Issue #50515, #51835)

  - A vulnerability exists due to a crash on shutdown via a
    notifications bug. (Issue #50553)

  - A vulnerability can be triggered in omnibox autosuggest
    if the user may be going to type a password.
    (Issue #51146)

  - A memory corruption vulnerability exists in ruby
    support. (Issue #51654)

  - A memory corruption vulnerability exists in Geolocation
    support. (Issue #51670)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82e215b9");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 5.0.375.127 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/20");

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
google_chrome_check_version(installs:installs, fix:'5.0.375.127', severity:SECURITY_HOLE);
