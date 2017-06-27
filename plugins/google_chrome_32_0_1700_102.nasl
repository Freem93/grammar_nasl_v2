#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72167);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/09/29 20:31:25 $");

  script_cve_id("CVE-2013-6649", "CVE-2013-6650", "CVE-2014-1681");
  script_bugtraq_id(65168, 65172, 65232);
  script_osvdb_id(102564, 102565, 102633);

  script_name(english:"Google Chrome < 32.0.1700.102 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 32.0.1700.102.  It is, therefore, affected by the following
vulnerabilities :

  - A use-after-free error exists related to processing
    SVG images. (CVE-2013-6649)

  - An unspecified error exists related to the V8 JavaScript
    engine could allow memory corruption. (CVE-2013-6650)

  - An unspecified security issue exists. (CVE-2014-1681)");
  # http://googlechromereleases.blogspot.com/2014/01/stable-channel-update_27.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1a3d9d7");
  # http://build.chromium.org/f/chromium/perf/dashboard/ui/changelog.html?url=/branches/1700/src&range=246481:243157&mode=html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ef3e6d9");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 32.0.1700.102 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'32.0.1700.102', severity:SECURITY_HOLE);
