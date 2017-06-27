#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62742);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/03 17:40:03 $");

  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_bugtraq_id(56301, 56302, 56306);
  script_osvdb_id(86773, 86774, 86775);

  script_name(english:"Thunderbird < 16.0.2 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a mail client that is potentially
affected by several vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Thunderbird is earlier than 16.0.2 and is
therefore potentially affected by the following security issues :
  
  - The true value of 'window.location' can be shadowed by
    user content through the use of the 'valueOf' method,
    which can be combined with some plugins to perform 
    cross-site scripting attacks. (CVE-2012-4194)

  - The 'CheckURL' function of 'window.location' can be
    forced to return the wrong calling document and 
    principal, allowing a cross-site scripting attack.
    (CVE-2012-4195)

  - It is possible to use property injection by prototype to
    bypass security wrapper protections on the 'Location'
    object, allowing the cross-origin reading of the 
    'Location' object. (CVE-2012-4196)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-90.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 16.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

mozilla_check_version(product:'thunderbird', version:version, path:path, esr:FALSE, fix:'16.0.2', skippat:'^10\\.0\\.', severity:SECURITY_WARNING, xss:TRUE);
