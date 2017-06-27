#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63645);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id(
    "CVE-2013-0839",
    "CVE-2013-0840",
    "CVE-2013-0841",
    "CVE-2013-0842"
  );
  script_bugtraq_id(59680, 59681, 59682, 59683);
  script_osvdb_id(89469, 89470, 89503, 89504);

  script_name(english:"Google Chrome < 24.0.1312.56 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 24.0.1312.56 and is, therefore, affected by the following
vulnerabilities :

  - A use-after-free vulnerability exists related to font
    handling and canvas. (CVE-2013-0839)

  - An error exists related to URL validation and the
    opening of new browser windows. (CVE-2013-0840)

  - An array index is not properly checked in relation to
    content blocking. (CVE-2013-0841)

  - An unspecified error exists related to handling null
    characters in embedded paths. (CVE-2013-0842)

Successful exploitation of some of these issues could lead to an
application crash or even allow arbitrary code execution, subject to the
user's privileges.");
  # http://googlechromereleases.blogspot.com/2013/01/stable-channel-update_22.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b40d638");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 24.0.1312.56 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/22");

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
google_chrome_check_version(installs:installs, fix:'24.0.1312.56', severity:SECURITY_HOLE);
