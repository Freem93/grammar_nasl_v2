#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(63338);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id(
    "CVE-2012-0428",
    "CVE-2012-0429",
    "CVE-2012-0430",
    "CVE-2012-0432"
  );
  script_bugtraq_id(57038);
  script_osvdb_id(88648, 88649, 88650, 88718);
  script_xref(name:"EDB-ID", value:"24205");
  script_xref(name:"EDB-ID", value:"24323");

  script_name(english:"Novell eDirectory 8.8.x Multiple Security Vulnerabilities");
  script_summary(english:"Checks version of eDirectory from an ldap search");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote directory service is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running eDirectory, a directory service software
from Novell.  The installed version of Novell eDirectory is affected by
multiple issues :

  - An unspecified cross-site scripting flaw exists.
    (CVE-2012-0428)

  - It is possible to trigger a remote denial of service 
    vulnerability by sending a malformed HTTP request. 
    (CVE-2012-0429)
 
  - An unspecified flaw may allow a remote attacker to gain 
    access to administrator cookie information. 
    (CVE-2012-0430)

  - There is an unspecified stack-based buffer overflow in 
    the Novell NCP implementation in eDirectory that has 
    unspecified impact. (CVE-2012-0432)"
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Jan/97");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=3426981");
  # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5152711.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10bd0c45");
  # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5152712.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?792f0ba4");
  # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5154239.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1efab384");
  # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5154251.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?caef468a");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7011539");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7011538");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7011533");
  script_set_attribute(attribute:"solution", value:"Upgrade to eDirectory 8.8 SP6 Patch 7 / 8.8 SP7 Patch 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell eDirectory 8 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);
  
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

ldap_port = get_service(svc:"ldap", default:389, exit_on_fail:TRUE);

edir_ldap = get_kb_item_or_exit('LDAP/'+ldap_port+'/vendorVersion');
if ("Novell eDirectory" >< edir_ldap) edir_product = chomp(strstr(edir_ldap, "Novell eDirectory"));
else audit(AUDIT_NOT_LISTEN, 'Novell eDirectory', ldap_port);

info = '';

# LDAP Agent for Novell eDirectory 8.8 SP7 (20703.00) : Patched
# LDAP Agent for Novell eDirectory 8.8 SP6 (20608.00) : Patched 
if (
  ereg(pattern:'^LDAP Agent for Novell eDirectory 8.8 *\\(([0-9]+)\\.([0-9]+)\\)$', string:edir_ldap) ||
  ereg(pattern:'^LDAP Agent for Novell eDirectory 8.8 *SP[0-5] *\\(([0-9]+)\\.([0-9]+)\\)$', string:edir_ldap) 
)
{ 
  info =  '\n  Installed Version       : ' + edir_product;
  info += '\n  Fixed Version : 8.8 SP6 Patch 7 / 8.8 SP7 Patch 2\n';
}
else if (ereg(pattern:'LDAP Agent for Novell eDirectory 8.8 SP[67]', string:edir_ldap))
{
  build_major = NULL;
  sp = NULL;

  matches = eregmatch(pattern:'^LDAP Agent for Novell eDirectory 8.8 *SP([67]) *\\(([0-9]+)\\.([0-9]+)\\)$', string:edir_ldap);
  if (matches) 
  {  
    sp = matches[1]; 
    build_major = matches[2];
  }

  if (!isnull(sp))
  {
    if (int(sp) == 6)
    {
      if (isnull(build_major) || int(build_major) < 20608)
      {
        info =  '\n  Installed version : ' + edir_product;
        info += '\n  Fixed version     : 8.8 SP6 Patch 7 (20608.00)\n';
      }
    }
    else if (int(sp) == 7)
    {
      if (isnull(build_major) || int(build_major) < 20703)
      { 
        info =  '\n  Installed version : ' + edir_product;
        info += '\n  Fixed version     : 8.8 SP7 Patch 2 (20703.00)\n';
      }
    }
  }
}

if (info)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\nThe following vulnerable Novell eDirectory instance was found : \n' + info;
    security_hole(port:ldap_port, extra:report);
  }
  else security_hole(ldap_port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, edir_product, ldap_port);
