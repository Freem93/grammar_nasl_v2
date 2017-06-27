#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35688);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2009-0609");
  script_bugtraq_id(33761);
  script_osvdb_id(52513);
  script_xref(name:"Secunia", value:"33923");

  script_name(english:"Sun Java System Directory Server 6.x < 6.3.1 LDAP JDBC Backend DoS");
  script_summary(english:"Checks the version of Sun Java System Directory Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server is affected by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Sun Java System Directory Server, an
LDAP server from Sun Microsystems.  

The installed version is older than 6.3.1, and the proxy server
included with such versions is reportedly affected by a denial of
service vulnerability.  By sending a specially crafted request to the
JDBC backend through the proxy server, an unauthenticated, remote
attacker may be able to trigger a denial of service condition." );
 script_set_attribute(attribute:"see_also", value:
"http://download.oracle.com/sunalerts/1020026.1.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java System Directory Server version 6.3.1." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);
 
 script_set_attribute(attribute:"patch_publication_date", value: "2009/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/13");
 script_cvs_date("$Date: 2016/05/13 15:33:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/ldap");
if (!port) port = 389;

ver = get_kb_item(string("LDAP/",port,"/vendorVersion"));

if (!ver) exit(0);

if (ereg(pattern:"^Sun-Java\(tm\)-System-Directory/6.([0-2]($|\.)|3$)",string:ver))
{
  if (report_verbosity > 0)
  {  
    ver = ver - "Sun-Java(tm)-System-Directory/";
  
    report = string(
      "\n",
      "Sun Java System Directory Server version ",ver, " is installed on\n",
      "the remote host.\n"
      );
     security_warning(port:port, extra:report);
  }
  else 
   security_warning(port);
}
