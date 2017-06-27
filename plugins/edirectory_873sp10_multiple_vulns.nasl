#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34349);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2008-4478", "CVE-2008-4479", "CVE-2008-4480");
  script_bugtraq_id(31553);
  script_osvdb_id(50236, 50237);

  script_name(english:"Novell eDirectory < 8.7.3 SP10 FTF1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of eDirectory from an LDAP search");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote directory service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running eDirectory, a directory service software
from Novell.  The installed version of Novell eDirectory is affected
by multiple heap overflows and denial of service vulnerabilities :

  - DS module is affected by two heap overflow vulnerabilities
    (Bugs 407275, 407256).

  - EMBOX module is affected by two denial of service vulnerabilities
    (Bugs 407243, 407245).");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-063");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-064");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-065");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-066");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/497163/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/497164/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/497165/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/497169/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=3477912");
  script_set_attribute(attribute:"solution", value:"Upgrade to eDirectory 8.7.3 SP10 FTF1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/07");
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

include("global_settings.inc");

ldap_port = get_kb_item("Services/ldap");
if (isnull(ldap_port)) ldap_port = 389;

if (!get_port_state(ldap_port)) exit(1,"Port "+ ldap_port + " is not open.");

edir_ldap = get_kb_item(string("LDAP/",ldap_port,"/vendorVersion"));
if ( isnull(edir_ldap) || "Novell eDirectory" >!< edir_ldap ) exit(0);

# LDAP Agent for Novell eDirectory 8.7.3.10 (10555.95)
# LDAP Agent for Novell eDirectory 8.7.3.10 (10557.10)

patchmaj = NULL; patchmin = NULL;
if ("LDAP Agent for Novell eDirectory 8.7.3.10" >< edir_ldap)
{
 v = eregmatch(pattern: "^LDAP Agent for Novell eDirectory 8\.7\.3\.10 \(([0-9]+)\.([0-9]+)\)", string: edir_ldap);
 if (! isnull(v))
 {
   patchmaj = int(v[1]);
   patchmin = int(v[2]);
 }
}

if ( ereg(pattern:"^LDAP Agent for Novell eDirectory ([0-7]\.|8\.([0-6][^0-9]|7\.([0-2]|3[^.0-9]|3\.[0-9][^0-9])))",string:edir_ldap) ||
    ! isnull(patchmaj) && (patchmaj < 10557 || patchmaj == 10557 && patchmin < 10)
   )
{ 
  if(report_verbosity)
  {
    edir_product = strstr(edir_ldap,"Novell eDirectory");
    edir_product = edir_product - strstr(edir_product , "("); #)
    report = strcat('\n ', edir_product, ' is installed on the remote host.\n');
    security_hole(port:ldap_port, extra:report);
  }
  else
    security_hole(ldap_port); 
}

