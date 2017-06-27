#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34221);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id(
    "CVE-2008-5091",
    "CVE-2008-5092",
    "CVE-2008-5093",
    "CVE-2008-5094",
    "CVE-2008-5095"
  );
  script_bugtraq_id(30947);
  script_osvdb_id(48204, 48206, 48207, 48208, 48209, 48210, 48211, 50960);
  script_xref(name:"Secunia", value:"31684");

  script_name(english:"Novell eDirectory < 8.8 SP3 Multiple Vulnerabilities (OF, XSS, MC)");
  script_summary(english:"Checks version of eDirectory from an LDAP search");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote directory service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running eDirectory, a directory service software
from Novell.  The installed version of Novell eDirectory is affected
by multiple issues :

  - NDS module is affected by a heap overflow vulnerability 
    (Bugs 396819 and 396817).

  - Windows installs of eDirectory NDS module are affected 
    by a remote memory corruption vulnerability (Bug 373852).

  - LDAP module is affected by a buffer overflow 
    vulnerability (Bug 373853).

  - Windows installs of eDirectory LDAP module are affected
    by a memory corruption DoS (Bug 359982).

  - HTTPSTK is affected by two heap overflow vulnerabilities 
    affecting 'Language' and 'Content Length' headers in 
    HTTPSTK (Bugs 379882 and 379880).

  - HTTPSTK is also affected by a cross-site scripting 
    vulnerability (Bug 387429).");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_set_attribute(attribute:"solution", value:"Upgrade to eDirectory 8.8 SP3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ldap_port = get_service(svc:"ldap", default:389, exit_on_fail:TRUE);

edir_ldap = get_kb_item_or_exit('LDAP/'+ldap_port+'/vendorVersion');
if ("Novell eDirectory" >!< edir_ldap) 
  audit(AUDIT_NOT_LISTEN, 'eDirectory', ldap_port);

edir_product = edir_ldap - 'LDAP Agent for ';

# LDAP Agent for Novell eDirectory 8.7.3.10 (10555.95)
# LDAP Agent for Novell eDirectory 8.7.3 (10552.72)
# LDAP Agent for Novell eDirectory 8.8 (20114.35) 
# LDAP Agent for Novell eDirectory 8.8 SP1 (20114.57) # unpatched
# LDAP Agent for Novell eDirectory 8.8 SP2 (20216.46) # unpatched
# LDAP Agent for Novell eDirectory 8.8 SP3 (20216.73) # patched

if (
  ereg(pattern:"^LDAP Agent for Novell eDirectory ([0-7]\.|8\.[0-6]([^0-9]|$))",string:edir_ldap)  	     ||
  ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *SP[12] *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap) ||
  ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap)
)
{ 
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    edir_product = strstr(edir_ldap,"Novell eDirectory");
    edir_product = edir_product - strstr(edir_product , "(");

    report = string(
      "\n",
      " ",edir_product," is installed on the remote host.\n"
       );
       security_hole(port:ldap_port, extra:report);
   }
   else security_hole(ldap_port); 
   exit(0);
} 
else audit(AUDIT_LISTEN_NOT_VULN, edir_product, ldap_port);
