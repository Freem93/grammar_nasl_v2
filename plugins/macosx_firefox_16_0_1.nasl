#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62585);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2012-4191", "CVE-2012-4192", "CVE-2012-4193");
  script_bugtraq_id(56153, 56154, 56155);
  script_osvdb_id(86125, 86126, 86128);

  script_name(english:"Firefox < 16.0.1 Multiple Vulnerabilities (Mac OS X)");
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
"The installed version of Firefox is earlier than 16.0.1 and is
therefore potentially affected by the following security issues :

  - An unspecified error related to the WebSockets
    implementation and the function
    'mozilla::net::FailDelayManager::Lookup' can allow
    application crashes and potentially, arbitrary code
    execution. (CVE-2012-4191)

  - An unspecified error exists that can allow attackers to
    bypass the 'Same Origin Policy' and access the
    'Location' object. (CVE-2012-4192)

  - An error exists related to 'security wrappers' and the
    function 'defaultValue()' that can allow cross-site
    scripting attacks. (CVE-2012-4193)"
  );
  # http://www.thespanner.co.uk/2012/10/10/firefox-knows-what-your-friends-did-last-summer/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8993e6b4");
  # https://blog.mozilla.org/security/2012/10/10/security-vulnerability-in-firefox-16/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc43f3c3");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-88/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-89/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 16.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'16.0.1', skippat:'^10\\.0\\.', severity:SECURITY_HOLE, xss:TRUE);
