#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81021);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2015-0311", "CVE-2015-0312");
  script_bugtraq_id(72283, 72343);
  script_osvdb_id(117428, 117580);

  script_name(english:"Google Chrome < 40.0.2214.93 Flash Player Multiple Remote Code Execution (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 40.0.2214.93. It is, therefore, affected by the following
vulnerabilities :

  - A use-after-free error exists that allows an attacker to
    crash the application or execute arbitrary code.
    (CVE-2015-0311)

  - A double-free error exists that allows an attacker to
    crash the application or possibly execute arbitrary
    code. (CVE-2015-0312)");
  # http://googlechromereleases.blogspot.com/2015/01/stable-channel-update_26.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2bec23e");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb15-03.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 40.0.2214.93 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player ByteArray UncompressViaZlibVariant Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'40.0.2214.93', severity:SECURITY_HOLE, xss:FALSE);
