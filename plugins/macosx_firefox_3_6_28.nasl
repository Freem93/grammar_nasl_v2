#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58354);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/03 17:40:03 $");

  script_cve_id(
    "CVE-2012-0455",
    "CVE-2012-0456",
    "CVE-2012-0457",
    "CVE-2012-0458",
    "CVE-2012-0461",
    "CVE-2012-0463",
    "CVE-2012-0464"
  );
  script_bugtraq_id(
    52458,
    52459,
    52460,
    52461,
    52464,
    52465,
    52466
  );
  script_osvdb_id(
    80011,
    80012,
    80013,
    80015,
    80018,
    80020,
    80021
  );

  script_name(english:"Firefox 3.6.x < 3.6.28 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox 3.6.x is potentially affected by the
following security issues :
  
  - Multiple memory corruption issues. By tricking a user 
    into visiting a specially crafted page, these issues may 
    allow an attacker to execute arbitrary code in the 
    context of the affected application. (CVE-2012-0457, 
    CVE-2012-0461, CVE-2012-0463, CVE-2012-0464)

  - A security bypass vulnerability that can be exploited by 
    an attacker if the victim can be tricked into setting a 
    new home page by dragging a specially crafted link to 
    the 'home' button URL, which will set the user's home 
    page to a 'javascript:' URL. (CVE-2012-0458) 

  - An information disclosure vulnerability exists due to an 
    out of bounds read in SVG filters. (CVE-2012-0456)

  - A cross-site scripting vulnerability exists that can be 
    triggered by dragging and dropping 'javascript:' links 
    onto a frame. (CVE-2012-0455)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-13.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-19.html");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Firefox 3.6.28 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'3.6.28', min:'3.6', severity:SECURITY_HOLE, xss:TRUE);