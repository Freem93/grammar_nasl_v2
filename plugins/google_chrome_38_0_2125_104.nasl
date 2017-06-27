#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78475);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/11 20:19:26 $");

  script_cve_id(
    "CVE-2014-0558",
    "CVE-2014-0564",
    "CVE-2014-0569",
    "CVE-2014-8439"
  );
  script_bugtraq_id(70437, 70441, 70442, 71289);
  script_osvdb_id(113197, 113198, 113199, 115035);

  script_name(english:"Google Chrome < 38.0.2125.104 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 38.0.2125.104. It is, therefore, affected by the following
vulnerabilities due to the version of Adobe Flash bundled with the
application :

  - Multiple memory corruption issues due to improperly
    sanitized user-supplied input allow arbitrary code
    execution. (CVE-2014-0564, CVE-2014-0558)

  - An integer overflow issue due to improperly sanitized
    user-supplied input that allows arbitrary code
    execution. (CVE-2014-0569)

  - An arbitrary code execution vulnerability due to the
    handling of a dereferenced memory pointer.
    (CVE-2014-8439)");
  # http://googlechromereleases.blogspot.dk/2014/10/stable-channel-update_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?335e9fff");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 38.0.2125.104 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player casi32 Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'38.0.2125.104', severity:SECURITY_HOLE, xss:FALSE);
