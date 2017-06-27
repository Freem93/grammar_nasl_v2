#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61462);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 13:53:27 $");

  script_cve_id("CVE-2012-2862", "CVE-2012-2863");
  script_bugtraq_id(54897);
  script_osvdb_id(84510, 84511);

  script_name(english:"Google Chrome < 21.0.1180.75 Multiple PDF Viewer Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 21.0.1180.75 and is, therefore, affected by the following
vulnerabilities :

  - An unspecified use-after-free error exists in the PDF
    viewer. (CVE-2012-2862)

  - An unspecified out-of-bounds write error exists in the
    PDF viewer. (CVE-2012-2863)

Successful exploitation of either issue could lead to an application
crash or even allow arbitrary code execution, subject to the user's
privileges.");
  # http://googlechromereleases.blogspot.com/2012/08/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0bdcd33");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 21.0.1180.75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'21.0.1180.75', severity:SECURITY_WARNING);
