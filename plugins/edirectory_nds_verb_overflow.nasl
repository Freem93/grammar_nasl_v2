#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43030);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/06/01 15:58:36 $");

  script_cve_id("CVE-2009-0895");
  script_bugtraq_id(37184);
  script_osvdb_id(60589);

  script_name(english:"Novell eDirectory < 8.8.5.2 / 8.7.3.10 ftf2 'NDS Verb' Request Buffer Overflow");
  script_summary(english:"Checks version from an ldap search");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote directory service is affected by a remote buffer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running eDirectory, a directory service software
from Novell. 

The installed version of eDirectory is affected by a remote buffer
overflow vulnerability.  By sending a specially crafted 'NDS Verb 0x1'
request, it may be possible for an attacker to execute arbitrary code
subject to the privileges of the affected service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.novell.com/support/viewContent.do?externalId=7004912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.iss.net/threats/356.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to eDirectory 8.8.5.2 / 8.7.3.10 ftf2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");

ldap_port=get_kb_item("Services/ldap");

if (isnull(ldap_port)) ldap_port=389;
if (!get_port_state(ldap_port)) exit(1, "Port "+ldap_port+" is not open.");

edir_ldap = get_kb_item('LDAP/'+ldap_port+'/vendorVersion');

if (isnull(edir_ldap))
  exit(1, "The 'LDAP/"+ldap_port+"/vendorVersion' KB item is missing.");

if ('Novell eDirectory' >< edir_ldap)
{
  edir_product=strstr(edir_ldap,'Novell eDirectory');
  edir_product=edir_product-strstr(edir_product, '(');
}
else
  exit(0, "The directory service listening on port "+ldap_port+" is not from Novell.");

info = NULL;
if ("Novell eDirectory 8.8" >< edir_ldap)
{
  if(ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *SP[0-4][^0-9]",string:edir_ldap) ||
     ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap))
    info = string(" ", edir_product," is installed on the remote host.\n");

  else if ("LDAP Agent for Novell eDirectory 8.8 SP5 " >< edir_ldap)
  {
    build = NULL;
    matches = eregmatch(pattern:"^LDAP Agent for Novell eDirectory 8.8 *SP5 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap);
    if (!isnull(matches))
    {
      build = matches[1];

      if (isnull(build) || int(build) < 20502)
        info = string(" ", edir_product," is installed on the remote host.\n");
    }
  }
}

else if ("LDAP Agent for Novell eDirectory 8.7.3.10 " >< edir_ldap)
{
  build = rev = NULL;
  matches = eregmatch(pattern:"^LDAP Agent for Novell eDirectory 8.7.3.10 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap);
  if (!isnull(matches))
  {
    build = matches[1];
    rev = matches[2];

    if ((isnull(build) || int(build) < 10557) ||
        (int(build) == 10557 && isnull(rev)) ||
        (int(build) == 10557 && int(rev) < 28)
      )
      info = string(" ",edir_product," is installed on the remote host.\n");
  }
}
else if (ereg(pattern:"^LDAP Agent for Novell eDirectory ([0-7]\.|8\.([0-6][^0-9]|7\.([0-2][^0-9]|3[^.0-9]|3\.[0-9][^0-9])))",string:edir_ldap))
  info = string(" ",edir_product," is installed on the remote host.\n");

if(!isnull(info))
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      info
    );
    security_hole(port:ldap_port, extra:report);
  }
  else security_hole(ldap_port);
}
else exit(0, "Novell eDirectory "+ edir_product+ " listening on port "+ldap_port+" is not vulnerable.");
