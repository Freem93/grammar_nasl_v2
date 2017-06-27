#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47859);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id(
    "CVE-2010-2897",
    "CVE-2010-2898",
    "CVE-2010-2899",
    "CVE-2010-2900",
    "CVE-2010-2901",
    "CVE-2010-2902",
    "CVE-2010-2903"
  );
  script_bugtraq_id(41976);
  script_osvdb_id(66746, 66748, 66749, 66751, 66752, 66847, 66857);
  script_xref(name:"Secunia", value:"40743");

  script_name(english:"Google Chrome < 5.0.375.125 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 5.0.375.125.  As such, it is reportedly affected by multiple
vulnerabilities :

  - An unspecified error in the layout code allows memory
    contents to be disclosed. (Issue #42736)

  - An unspecified error exists in the handling of large
    canvases. (Issue #43813)

  - A memory corruption error exists in the rendering code.
    (Issue #47866)

  - A memory corruption error exists in the handling of SVG
    content. (Issue #48284)

  - An unspecified error exists regarding hostname name
    truncation and incorrect eliding. (Issue #48597)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8918636");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 5.0.375.125 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/27");

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
google_chrome_check_version(installs:installs, fix:'5.0.375.125', severity:SECURITY_HOLE);
