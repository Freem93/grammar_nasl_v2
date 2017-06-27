#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56757);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/03 17:40:03 $");

  script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
  script_bugtraq_id(50589, 50593, 50595);
  script_osvdb_id(76947, 76948, 76952);

  script_name(english:"Thunderbird 3.1 < 3.1.16 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an email client that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1 is earlier than 3.1.16. 
Such versions are potentially affected by the following security
issues :

  - There is an error within the JSSubScriptLoader that
    incorrectly unwraps 'XPCNativeWrappers'. By tricking
    a user into installing a malicious plug-in, an attacker
    could exploit this issue to execute arbitrary code.
    (CVE-2011-3647)

  - Certain invalid sequences are not handled properly in
    'Shift-JIS' encoding, which can allow cross-site 
    scripting attacks. (CVE-2011-3648)

  - Profiling JavaScript files with many functions can cause
    the application to crash. It may be possible to trigger
    this behavior even when the debugging APIs are not being
    used. (CVE-2011-3650)");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-46.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-47.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-49.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
# nb: make sure we have at least 3 parts for the check.
for (i=max_index(ver); i<3; i++)
  ver[i] = 0;

if (ver[0] == 3 && ver[1] == 1 && ver[2] < 16)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    info +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.1.16' + '\n';
    security_hole(port:0, extra:info);
  }
  else security_hole(0);
  exit(0);
}
else 
{
  if (ver[0] == 3 && ver[1] == 1) exit(0, "The Thunderbird "+version+" install is not affected.");
  else exit(0, "Thunderbird 3.1.x is not installed.");
}
