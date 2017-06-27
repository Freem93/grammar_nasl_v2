#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86210);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id("CVE-2015-1303", "CVE-2015-1304");
  script_osvdb_id(127802, 128254);
  script_bugtraq_id(76844);

  script_name(english:"Google Chrome < 45.0.2454.101 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 45.0.2454.101. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the DOM that allows a
    remote attacker to bypass the cross-origin policy.
    (CVE-2015-1303)

  - An flaw exists in the V8 JavaScript engine when handling
    Object.observe calls on access-checked objects. A remote
    attacker may exploit this to bypass the cross-origin
    policy. (CVE-2015-1304)");
  # http://googlechromereleases.blogspot.com/2015/09/stable-channel-update_24.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?19d6fcc8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 45.0.2454.101 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/30");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'45.0.2454.101', severity:SECURITY_HOLE);
