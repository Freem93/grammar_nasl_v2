#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86598);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id(
    "CVE-2015-7645",
    "CVE-2015-7647",
    "CVE-2015-7648"
  );
  script_osvdb_id(
    128853,
    128982,
    128983
  );

  script_name(english:"Google Chrome < 46.0.2490.80 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 46.0.2490.80. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple type confusion errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2015-7645,
    CVE-2015-7647, CVE-2015-7648)");
  # http://googlechromereleases.blogspot.com/2015/10/stable-channel-update_22.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?db041d42");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-27.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 46.0.2490.80 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/10/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'46.0.2490.80', severity:SECURITY_HOLE);
