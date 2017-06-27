#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44938);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2011/06/01 15:58:36 $");
  
  script_cve_id("CVE-2010-0666");
  script_bugtraq_id(38157);
  script_osvdb_id(62214);
  script_xref(name:"Secunia", value:"38491");

  script_name(english:"Novell eDirectory < 8.8 SP5 Patch 3 eMBox SOAP Request DoS");
  script_summary(english:"Checks version of eDirectory from an ldap search");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running eDirectory, a directory service software
from Novell.

The eMBox service included with the installed version of eDirectory is
affected by a denial of service vulnerability.  

By sending a specially crafted HTTP SOAP request, it may be possible
for a remote attacker to crash the remote service.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-024/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509814/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=548503");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_set_attribute(attribute:"solution", value:"Upgrade to eDirectory 8.8 SP5 Patch 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date"  , value:"2010/02/11");
  script_set_attribute(attribute:"patch_publication_date" , value:"2010/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
  script_dependencies("ldap_search.nasl", "http_version.nasl");
  script_require_ports("Services/ldap", 389, "Services/www", 8028, 8030);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

ldap_port = get_service(svc:"ldap", default:389, exit_on_fail:TRUE);
if (!get_port_state(ldap_port)) exit(0,"Port "+ ldap_port + " is not open.");

edir_ldap = get_kb_item("LDAP/" + ldap_port + "/vendorVersion");
if (isnull(edir_ldap))
  exit(1,"The 'LDAP/"+ldap_port+"/vendorVersion' KB item is missing.");

if("Novell eDirectory" >< edir_ldap)
{
  edir_product = strstr(edir_ldap,"Novell eDirectory");
  edir_product = edir_product - strstr(edir_product , "(");
}
else
  exit(0,"The remote directory service on port " + ldap_port + " does not appear to be from Novell.");

http_port = NULL;
if (report_paranoia < 2)
{
  found = 0;
  ports = add_port_in_list(list:get_kb_list("Services/www"), port:8028);
  ports = add_port_in_list(list:ports, port:8030);

  foreach port (ports)
  {
    banner = get_http_banner (port:port);
    if(!isnull(banner))
    {
      if (egrep(pattern:"Server: .*HttpStk/[0-9]+\.[0-9]+", string:banner))
      {
       # If we are looking at a banner from Novell eDirectory, send a 
       # POST request to see if eMBox service is running.

        postdata = '<?xml version="1.0"?>' + '\n' +
                   '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'+ '\n' +
                   '<SOAP-ENV:Header/><SOAP-ENV:Body><dispatch><Action>novell.embox.connmgr.serverinfo</Action>' +
                   '<Object/><Parameters/></dispatch></SOAP-ENV:Body></SOAP-ENV:Envelope>' + '\n';

        res = http_send_recv3(method: 'POST', 
                              item:  '/SOAP', 
                              data: postdata, 
                              port: port,
                              add_headers: make_array( 
                                'Content-Type', 'text/xml',
                                'SOAPAction', '"/novell.embox.connmgr.serverinfo"'));

        if (isnull(res))  exit(1, "The web server on port "+port+" failed to respond.");

        # if the service is running, we should see the SOAPAction in response. 
        if("novell.embox.connmgr.serverinfo" >< res[2])
        {
          http_port = port;
          found = 1;
          break;
        }
      }
    }
  }
  if(!found) exit(0, "Novell eDirectory eMBox service is not running on the remote host.");
}
if(isnull(http_port)) http_port = 0;

info = NULL;

# LDAP Agent for Novell eDirectory 8.8 SP5 (20219.14)
# LDAP Agent for Novell eDirectory 8.8 SP5 (20503.09) # patched
 
if ( ereg(pattern:"^LDAP Agent for Novell eDirectory ([0-7]\.|8.[0-7]([^0-9]|$))",string:edir_ldap)  	      ||
     ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *SP[1-4] *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap) ||
     ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap)
   )
   info = " " + edir_product + " is installed on the remote host." + '\n';	                

else if (ereg(pattern:"LDAP Agent for Novell eDirectory 8.8 SP5",string:edir_ldap))
{
  build = NULL;
  matches = eregmatch(pattern:"^LDAP Agent for Novell eDirectory 8.8 *SP5 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap);
  if(matches)
    build = matches[1];

  if(isnull(build) || int(build) < 20503)
    info = " " + edir_product + " is installed on the remote host." + '\n';
}
else
 exit(1, "Unknown Novell eDirectory version '"+ edir_ldap + "' on port " + ldap_port + ".");

if(!isnull(info))
{
  if (report_verbosity > 0)
  {
    report = '\n' + info ;
    security_warning(port:http_port, extra:report);
  }
  else security_warning(http_port);

  exit(0);
}
else exit(0, edir_product + " is listening on port " + ldap_port + " and is not affected." );
