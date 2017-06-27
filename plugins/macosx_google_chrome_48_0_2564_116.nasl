#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88957);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:10 $");

  script_cve_id("CVE-2016-1629");
  script_osvdb_id(134721);

  script_name(english:"Google Chrome < 48.0.2564.116 Blink Same-Origin Policy Bypass (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 48.0.2564.116. It is, therefore, affected by an unspecified
flaw related to the Blink rendering engine. An attacker can exploit
this to bypass same-origin policy restrictions and escape the sandbox,
allowing the attacker to execute arbitrary code with elevated
privileges.");
  # http://googlechromereleases.blogspot.com/2016/02/stable-channel-update_18.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?63641ede");
  script_set_attribute(attribute:"see_also",value:"http://www.chromium.org/blink");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 48.0.2564.116 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/25");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'48.0.2564.116', severity:SECURITY_HOLE);
