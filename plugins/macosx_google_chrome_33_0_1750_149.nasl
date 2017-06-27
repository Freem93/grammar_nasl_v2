#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72940);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/03 17:40:03 $");

  script_cve_id(
    "CVE-2014-1700",
    "CVE-2014-1701",
    "CVE-2014-1702",
    "CVE-2014-1703",
    "CVE-2014-1704"
  );
  script_bugtraq_id(66120);
  script_osvdb_id(104015, 104338, 104339, 104340, 104341, 104342, 104343);

  script_name(english:"Google Chrome < 33.0.1750.149 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is a
version prior to 33.0.1750.149.  It is, therefore, affected by the
following vulnerabilities :

  - Use-after-free errors exist related to 'speech' and
    'web database' processing. (CVE-2014-1700,
    CVE-2014-1702)

  - An input validation error exists related to 'events'
    handling that could allow universal cross-site
    scripting (UXSS) attacks. (CVE-2014-1701)

  - A use-after-free error exists related to 'web sockets'
    that could allow sandbox protection bypass.
    (CVE-2014-1703)

  - Multiple unspecified errors exist related to the V8
    JavaScript engine. (CVE-2014-1704)");
  # http://googlechromereleases.blogspot.com/2014/03/stable-channel-update_11.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab397f6f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 33.0.1750.149 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'33.0.1750.149', severity:SECURITY_HOLE, xss:TRUE);
