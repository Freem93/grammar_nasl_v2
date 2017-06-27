#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39805);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2009-0192", "CVE-2009-2456", "CVE-2009-2457");
  script_bugtraq_id(35666);
  script_osvdb_id(55847, 55848, 55849);
  script_xref(name:"Secunia", value:"34160");

  script_name(english:"Novell eDirectory < 8.8 SP5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of eDirectory from an LDAP search");

  script_set_attribute(attribute:"synopsis", value:
"The remote directory service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running eDirectory, a directory service software
from Novell.  The installed version of this software is affected by
multiple issues :

  - Malformed bind LDAP packet causes eDir crash.
    (Bug 492692)

  - The use of multiple wildcards in RDNs can trigger a
    remote denial of service vulnerability. (Bug 458504)

  - An HTTP request containing a specially crafted
    'Accept-Language' header can trigger a stack-based
    buffer overflow. This issue affects the iMonitor
    service. (Bugs 484007 and 446342)");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-13/");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_set_attribute(attribute:"solution", value:"Upgrade to eDirectory 8.8 SP5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/15");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");

ldap_port = get_kb_item("Services/ldap");
if (!ldap_port) ldap_port = 389;
if (!get_port_state(ldap_port)) exit(0, "Port "+ldap_port+" is not open.");

edir_ldap = get_kb_item(string("LDAP/",ldap_port,"/vendorVersion"));
if (isnull(edir_ldap) || "Novell eDirectory" >!< edir_ldap) 
  exit(0, "Remote LDAP server does not appear to be using eDirectory.");

if (
  ereg(pattern:"^LDAP Agent for Novell eDirectory ([0-7]\.|8\.[0-7]([^0-9]|$))", string:edir_ldap) ||
  ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap) ||
  ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *SP[0-4] *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap)
)
{
  if(report_verbosity > 0)
  {
    edir_product = strstr(edir_ldap,"Novell eDirectory");
    edir_product = edir_product - strstr(edir_product, "(");

    report = string(
      "\n",
      "  ", edir_product, " is installed on the remote host.\n"
    );
    security_warning(port:ldap_port, extra:report);
  }
  else security_warning(port:ldap_port);

  exit(0);
}
exit(0, "The remote eDirectory install is not affected.");
