#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(57035);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/08/17 15:01:43 $");

  script_cve_id("CVE-2011-3849");
  script_bugtraq_id(50699);
  script_osvdb_id(77188);

  script_name(english:"CA eTrust Directory SNMP Packet Parsing Denial of Service");
  script_summary(english:"Queries LDAP server for DXserver version");

  script_set_attribute(attribute:"synopsis", value:
"The remote directory server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"CA eTrust Directory, a directory service application, is installed on
the remote host.  Versions of CA eTrust Directory 8.1 and R12 earlier
than service pack 7 CR1 are potentially affected by a denial of
service vulnerability due to the way the application parses SNMP
packets.  A remote, unauthenticated attacker could exploit this flaw
to crash the affected service.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?845ff19e");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520547/100/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to CA eTrust Directory R12 SP7 CR1 (build 6279) or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:etrust_directory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 19289, 19389, 19489);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

ldap_port = get_service(svc:'ldap', default:19389, exit_on_fail:TRUE);

ca_ldap = get_kb_item_or_exit('LDAP/'+ldap_port+'/dxServerVersion');

# Make sure it is CA Directory Server
if ('DXserver' >!< ca_ldap) exit(0, 'The LDAP server listening on port ' + ldap_port +' does not appear to be CA Directory Server.');
ca_prod = ca_ldap - strstr(ca_ldap, ')');
ca_prod += ')';
if (ca_prod !~ '^DXserver r[0-9\\.]+ \\(build [0-9]+\\)') exit(1, 'Invalid version (' + ca_ldap + ') obtained from the CA Directory Server listening on port '+ldap_port+'.');

info = '';
if (ereg(pattern:'^DXserver r8\\.1[^0-9]', string:ca_prod))
  info = ca_prod;
else if (ereg(pattern:'^DXserver r12[^0-9]', string:ca_prod))
{
  build = NULL;
  matches = eregmatch(pattern:'^DXserver r12[^\\(]+\\(build ([0-9]+)\\)$', string:ca_prod);
  if (matches) build = matches[1];

  if (isnull(build)) exit(1, 'Failed to get the build number from the CA Directory Server listening on port '+ldap_port+'.');
  if (int(build) < 6279) info = ca_prod;
}

if (info)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + ca_ldap +
      '\n  Installed version : ' + ca_prod +
      '\n  Fixed version     : DXserver r12 (build 6279)\n';
    security_warning(port:ldap_port, extra:report);
  }
  else security_warning(ldap_port);
  exit(0);
}
else exit(0, ca_prod + ' is listening on port '+ldap_port+' and is not affected.');
