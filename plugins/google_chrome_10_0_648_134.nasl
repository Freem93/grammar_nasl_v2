# @DEPRECATED@
#
# This release of Chrome only corrected the Flash Player issue as
# documented by flash_player_apsa11-01.nasl.
# Disabled on 2011/05/23. Deprecated by flash_player_apsa11-01.nasl
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52713);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/11/13 21:35:39 $");

  script_cve_id("CVE-2011-0609");
  script_bugtraq_id(46860);
  script_osvdb_id(71254);
  script_xref(name:"CERT", value:"192052");
  script_xref(name:"Secunia", value:"43757");

  script_name(english:"Google Chrome < 10.0.648.134 Unspecified Adobe Flash Player");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a code
execution vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 10.0.648.134.  Such versions of Chrome contain a vulnerable version
of Adobe Flash Player. 

A remote attacker could exploit this by tricking a user into viewing
unspecified, malicious SWF content, resulting in arbitrary code
execution. 

This bug is currently being exploited in the wild.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa11-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29279e96");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 10.0.648.134 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player AVM Bytecode Verification');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
exit(0);

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'10.0.648.134', severity:SECURITY_HOLE);
