#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58563);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2011-1101");
  script_bugtraq_id(46529, 52522);
  script_osvdb_id(71038, 71041, 80185);

  script_name(english:"Citrix Licensing Server Administration Components Multiple Vulnerabilities");
  script_summary(english:"Checks version of Citrix Licensing Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix License Server installed on the remote Windows
host is potentially affected by multiple vulnerabilities in the
administration component :

  - An unspecified cross-site scripting vulnerability 
    exists.

  - An unspecified cross-site request forgery vulnerability
    exists.

  - A denial of service vulnerability exists that could 
    allow an attacker with access to the web application
    to prevent access by other legitimate users.");

  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX128167");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Mar/159");
  script_set_attribute(attribute:"solution", value:"Upgrade to Citrix License Server 11.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:licensing_administration_console");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("citrix_licensing_installed.nasl");
  script_require_keys("SMB/Citrix License Server/Path", "SMB/Citrix License Server/Version", "SMB/Citrix License Server/Build");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit('SMB/Citrix License Server/Path');
version = get_kb_item_or_exit('SMB/Citrix License Server/Version');
build = get_kb_item_or_exit('SMB/Citrix License Server/Build');

fix = '11.10.0.0';
if (report_paranoia < 2)
{
  kb = get_kb_item('SMB/Citrix License Server/LMC');
  if (
    isnull(kb) || 
    (kb == FALSE && ver_compare(ver:version, fix:fix) == -1)
  ) exit(0, 'Citrix License Server Administration Console is not installed with Citrix License Server.');
}

if (ver_compare(ver:version, fix:fix) == -1)
{
  port = get_kb_item('SMB/transport');
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The Citrix License Server '+version+' build '+build+' install in '+path+' is not affected.');
