#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47022);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/04/26 19:03:07 $");

  script_cve_id("CVE-2009-4653");
  script_bugtraq_id(37009, 40541);
  script_osvdb_id(62661, 65145, 65146, 65147);
  script_xref(name:"Secunia", value:"40041");

  script_name(english:"Novell eDirectory < 8.8 SP5 Patch 4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of eDirectory from an LDAP search");

  script_set_attribute(attribute:"synopsis", value:
"The remote directory service is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running eDirectory, a directory service software
from Novell.  The installed version of this software is affected by
one or more of the following vulnerabilities :

  - A denial of service vulnerability in NDSD when handling
    a malformed verb. (Bug 571244)

  - A stack-based buffer overflow in the dhost module
    for Windows. (Bug 588883)

  - A predictable session cookie in DHOST. (Bug 586854)");

  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/507812/100/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to eDirectory 8.8 SP5 Patch 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

ldap_port = get_service(svc:"ldap", default:389, exit_on_fail:TRUE);

edir_ldap = get_kb_item('LDAP/'+ldap_port+'/vendorVersion');
if (isnull(edir_ldap))
  exit(1,"The 'LDAP/"+ldap_port+"/vendorVersion' KB item is missing.");

if ("Novell eDirectory" >< edir_ldap)
{
  edir_product = strstr(edir_ldap,"Novell eDirectory");
  edir_product = edir_product - strstr(edir_product, "(");
}
else exit(0, "The remote directory service on port " + ldap_port + " does not appear to be from Novell.");

info = '';
if (
  ereg(pattern:'^LDAP Agent for Novell eDirectory ([0-7]\\.|8\\.[0-7]([^0-9]|$))', string:edir_ldap) ||
  ereg(pattern:'^LDAP Agent for Novell eDirectory 8.8 *\\(([0-9]+)\\.([0-9]+)\\)$', string:edir_ldap) ||
  ereg(pattern:'^LDAP Agent for Novell eDirectory 8.8 *SP[0-4] *\\(([0-9]+)\\.([0-9]+)\\)$', string:edir_ldap) 
) info = ' ' + edir_product + ' is installed on the remote host.' + '\n';
else if (ereg(pattern:'LDAP Agent for Novell eDirectory 8.8 SP5', string:edir_ldap))
{
  build = NULL;
  matches = eregmatch(pattern:'^LDAP Agent for Novell eDirectory 8.8 *SP5 *\\(([0-9]+)\\.([0-9]+)\\)$', string:edir_ldap);
  if (matches) build = matches[1];

  if (isnull(build) || int(build) < 20504)
    info = ' ' + edir_product + ' is installed on the remote host.' + '\n';
}
else exit(1, "Unknown Novell eDirectory version '" + edir_ldap + "' on port " + ldap_port + ".");

if (info)
{
  if (report_verbosity > 0)
  {
    report = '\n' + info;
    security_hole(port:ldap_port, extra:report);
  }
  else security_hole(ldap_port);
  exit(0);
}
else exit(0, edir_product + '  is listening on port ' + ldap_port + '  and is not affected.');
