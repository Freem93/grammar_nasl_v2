#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79141);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 20:19:26 $");

  script_cve_id(
    "CVE-2014-0573",
    "CVE-2014-0574",
    "CVE-2014-0576",
    "CVE-2014-0577",
    "CVE-2014-0581",
    "CVE-2014-0582",
    "CVE-2014-0583",
    "CVE-2014-0584",
    "CVE-2014-0585",
    "CVE-2014-0586",
    "CVE-2014-0588",
    "CVE-2014-0589",
    "CVE-2014-0590",
    "CVE-2014-8437",
    "CVE-2014-8438",
    "CVE-2014-8440",
    "CVE-2014-8441",
    "CVE-2014-8442"
  );
  script_bugtraq_id(
    71033,
    71035,
    71036,
    71037,
    71038,
    71039,
    71040,
    71041,
    71042,
    71043,
    71044,
    71045,
    71046,
    71047,
    71048,
    71049,
    71050,
    71051
  );
  script_osvdb_id(
    114487,
    114488,
    114489,
    114490,
    114491,
    114492,
    114493,
    114494,
    114495,
    114496,
    114497,
    114498,
    114499,
    114500,
    114501,
    114502,
    114503,
    114504
  );

  script_name(english:"Google Chrome < 38.0.2125.122 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is a
version prior to 38.0.2125.122. It is, therefore, affected by the
following vulnerabilities due to the version of Adobe Flash bundled
with the application :

  - Multiple memory corruption vulnerabilities allow an
    attacker to execute arbitrary code. (CVE-2014-0576,
    CVE-2014-0581, CVE-2014-8440, CVE-2014-8441)

  - Multiple use-after-free vulnerabilities could result in
    arbitrary code execution. (CVE-2014-0573, CVE-2014-0588,
    CVE-2014-8438, CVE-2014-0574)

  - Multiple type confusion vulnerabilities could result in
    arbitrary code execution. (CVE-2014-0577, CVE-2014-0584,
    CVE-2014-0585, CVE-2014-0586, CVE-2014-0590)

  - Multiple heap-based buffer overflow vulnerabilities can
    be exploited to execute arbitrary code or elevate
    privileges. (CVE-2014-0583, CVE-2014-0582,
    CVE-2014-0589)

  - A permission issue that allows a remote attacker to gain
    elevated privileges. (CVE-2014-8442)

  - An information disclosure vulnerability can be exploited
    to disclose secret session tokens. (CVE-2014-8437)");

  # http://googlechromereleases.blogspot.com/2014/11/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb7317d6");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 38.0.2125.122 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player UncompressViaZlibVariant Uninitialized Memory');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

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

google_chrome_check_version(installs:installs, fix:'38.0.2125.122', severity:SECURITY_HOLE, xss:FALSE);
