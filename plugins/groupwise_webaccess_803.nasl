#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62416);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id("CVE-2012-0272", "CVE-2012-4912");
  script_bugtraq_id(55633, 55814);
  script_osvdb_id(85664, 85800);

  script_name(english:"Novell GroupWise WebAccess 8.x < 8.0.3 Multiple XSS Vulnerabilities");
  script_summary(english:"Checks version of GWINTER.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise installed on the remote Windows host is
earlier than 8.0.3.  It is, therefore, reportedly affected by multiple
cross-site scripting vulnerabilities :

  - The application fails to sanitize user-supplied input to
    the 'merge' parameter of the 'Search Document' form. 
    (CVE-2012-0272)

  - HTML email is not properly sanitized before being 
    displayed to the user. (CVE-2012-4912)

A remote attacker may be able to exploit these vulnerabilities to
execute arbitrary script code in the browser of an unsuspecting user in
the context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7010368");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7010768");
  script_set_attribute(attribute:"solution", value:"Upgrade to GroupWise WebAccess 8.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("groupwise_webaccess_detect.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/GroupWise WebAccess/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

version = get_kb_item_or_exit("SMB/GroupWise WebAccess/Version");
path = get_kb_item_or_exit("SMB/GroupWise WebAccess/Path");

# Unless we're paranoid, make sure the service is running.
if (report_paranoia < 2)
{
  service = get_kb_item_or_exit("SMB/GroupWise WebAccess/Service");
  status = get_kb_item_or_exit("SMB/svc/"+service);
  if (status != SERVICE_ACTIVE)
    exit(0, "The GroupWise WebAccess service is installed but not active.");
}

fixed_version = '8.0.3.21395';
if (version =~ '^8\\.' && ver_compare(ver:version, fix:fixed_version) == -1)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_warning(get_kb_item('SMB/transport'));
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'GroupWise WebAccess', version, path);
