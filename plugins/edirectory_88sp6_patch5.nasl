#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61709);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/30 10:48:39 $");

  script_cve_id("CVE-2010-1929");
  script_bugtraq_id(40480, 55157);
  script_osvdb_id(65737, 80094, 80095);

  script_name(english:"Novell eDirectory < 8.8 SP6 Patch 5 Multiple Vulnerabilities");
  script_summary(english:"Checks eDir version/build");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote directory service is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running eDirectory, a directory service application
from Novell.  According to its self-reported version number, this
software is affected by multiple stack-based buffer overflow and memory
corruption vulnerabilities.  A remote, unauthenticated attacker could
exploit the most severe of these vulnerabilities to execute arbitrary
code."
  );
  # http://www.coresecurity.com/content/novell-imanager-buffer-overflow-off-by-one-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81dcddd7");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-146/");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7009947");
  script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=bqt3K-sXJEs~");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=3426981");
  script_set_attribute(attribute:"solution", value:"Upgrade to eDirectory 8.8 SP6 Patch 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ldap_port = get_service(svc:"ldap", default:389, exit_on_fail:TRUE);
edir_ldap = get_kb_item_or_exit('LDAP/'+ldap_port+'/vendorVersion');

if ("Novell eDirectory" >< edir_ldap)
  edir_product = edir_ldap - 'LDAP Agent for ';
else
  audit(AUDIT_NOT_LISTEN, 'eDirectory', ldap_port);

info = '';
if (
  ereg(pattern:'^LDAP Agent for Novell eDirectory ([0-7]\\.|8\\.[0-7]([^0-9]|$))', string:edir_ldap) ||
  ereg(pattern:'^LDAP Agent for Novell eDirectory 8.8 *\\(([0-9]+)\\.([0-9]+)\\)$', string:edir_ldap) ||
  ereg(pattern:'^LDAP Agent for Novell eDirectory 8.8 *SP[0-5] *\\(([0-9]+)\\.([0-9]+)\\)$', string:edir_ldap) 
) info = ' ' + edir_product + ' is installed on the remote host.' + '\n';
else if (ereg(pattern:'LDAP Agent for Novell eDirectory 8.8 SP6', string:edir_ldap))
{
  build = NULL;
  matches = eregmatch(pattern:'^LDAP Agent for Novell eDirectory 8.8 *SP6 *\\(([0-9]+)\\.([0-9]+)\\)$', string:edir_ldap);
  if (matches) build = matches[1];

  if (int(build) >= 20606)
    audit(AUDIT_LISTEN_NOT_VULN, edir_product, ldap_port);
}
else audit(AUDIT_LISTEN_NOT_VULN, edir_product, ldap_port);

if (report_verbosity > 0)
{
  report = '\n' + edir_product + ' is installed on the remote host.\n';
  security_hole(port:ldap_port, extra:report);
}
else security_hole(ldap_port);
