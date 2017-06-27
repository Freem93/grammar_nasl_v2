#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89786);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/09/15 13:52:58 $");

  script_cve_id(
    "CVE-2016-1643",
    "CVE-2016-1644",
    "CVE-2016-1645"
  );
  script_osvdb_id(
    135649,
    135650,
    135651
  );

  script_name(english:"Google Chrome < 49.0.2623.87 Multiple RCE");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 49.0.2623.87. It is, therefore, affected by multiple
vulnerabilities :

  - A type confusion error exists in the Blink rendering
    engine that allows a remote attacker, via a malicious
    website, to execute arbitrary code. (CVE-2016-1643)

  - A use-after-free error exists in the Blink rendering
    engine that allows a remote attacker, via a malicious
    website, to deference already freed memory, resulting
    in the execution of arbitrary code. (CVE-2016-1644)

  - An out-of-bounds write error exists in PDFium, the PDF
    rendering library, that allows a remote attacker to
    manipulate the system memory, resulting the execution
    of arbitrary code. (CVE-2016-1645)");
  # http://googlechromereleases.blogspot.com/2016/03/stable-channel-update_8.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?26e58257");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 49.0.2623.87 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/09");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'49.0.2623.87', severity:SECURITY_HOLE);
