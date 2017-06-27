#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76582);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/09/26 02:05:46 $");

  script_cve_id("CVE-2014-3160", "CVE-2014-3162");
  script_bugtraq_id(68677);
  script_osvdb_id(109212, 109213);

  script_name(english:"Google Chrome < 36.0.1985.125 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
a version prior to 36.0.1985.125. It is, therefore, affected by
multiple vulnerabilities allowing an attacker to compromise the
integrity of the system via unspecified vectors.");
  # http://googlechromereleases.blogspot.com/2014/07/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03fe45fe");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 36.0.1985.125 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'36.0.1985.125', severity:SECURITY_WARNING, xss:FALSE);
