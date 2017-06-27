#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71969);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id(
    "CVE-2013-6641",
    "CVE-2013-6643",
    "CVE-2013-6644",
    "CVE-2013-6645",
    "CVE-2013-6646"
  );
  script_bugtraq_id(64805, 64981, 65066);
  script_osvdb_id(
    101985,
    101986,
    101987,
    101988,
    101989,
    101990,
    101991,
    102128,
    102139,
    102140,
    102141,
    102142,
    102302,
    102303,
    102304,
    102305,
    102306,
    102307,
    102308,
    102309,
    102349,
    102412
  );

  script_name(english:"Google Chrome < 32.0.1700.77 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is a
version prior to 32.0.1700.77.  It is, therefore, affected by the
following vulnerabilities :

  - Use-after-free errors exist related to forms, web
    workers and speech input elements. (CVE-2013-6641,
    CVE-2013-6645, CVE-2013-6646)

  - An unspecified error exists related to Google accounts
    and the sync process. (CVE-2013-6643)

  - Various unspecified errors exist having unspecified
    impacts. (CVE-2013-6644)

  - An input validation error exists related to the
    included WebKit component 'XSS Auditor' and the
    handling of the 'srcdoc' attribute that could allow
    cross-site scripting attacks. (VulnDB #102412)");
  # http://googlechromereleases.blogspot.com/2014/01/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13bff2a9");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 32.0.1700.77 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'32.0.1700.77', severity:SECURITY_WARNING, xss:TRUE);
