#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83137);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/24 04:37:33 $");

  script_cve_id("CVE-2015-1243","CVE-2015-1250");
  script_bugtraq_id(74389);

  script_name(english:"Google Chrome < 42.0.2311.135 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 42.0.2311.135. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified user-after-free memory error exists in
    DOM. (CVE-2015-1243)

  - Other unspecified errors exists. No other details are
    available. (CVE-2015-1250)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.ca/2015/04/stable-channel-update_28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f54c26a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 42.0.2311.135 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");

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

google_chrome_check_version(fix:'42.0.2311.135', severity:SECURITY_HOLE);
