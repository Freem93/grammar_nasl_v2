#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55460);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id(
    "CVE-2011-2345",
    "CVE-2011-2346",
    "CVE-2011-2347",
    "CVE-2011-2348",
    "CVE-2011-2349",
    "CVE-2011-2350",
    "CVE-2011-2351"
  );
  script_bugtraq_id(48479);
  script_osvdb_id(73504, 73506, 73507, 73508, 73509, 73510, 73511);

  script_name(english:"Google Chrome < 12.0.742.112 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 12.0.742.112.  As such, it is affected by the following
vulnerabilities :

  - An out-of-bounds read in NPAPI string handling exists.
    (Issue #77493)

  - A use-after-free issue exists in SVG font handling.
    (Issue #84355)

  - A memory corruption issue exists in CSS parsing.
    (Issue #85003)

  - Multiple lifetime and re-entrancy issues exist in the
    HTML parser. (Issue #85102)

  - A bad bounds check exists in v8. (Issue #85177)

  - A use-after-free issue exists with the SVG use element.
    (Issue #85211)

  - A use-after-free issue exists in text selection.
    (Issue #85418)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0153f07f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 12.0.742.112 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");

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
google_chrome_check_version(installs:installs, fix:'12.0.742.112', severity:SECURITY_HOLE);
