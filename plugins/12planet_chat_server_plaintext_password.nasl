#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11591);
 script_version ("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/01/05 18:44:51 $");

 script_bugtraq_id(7354);
 script_osvdb_id(50429);
 # NOTE: no CVE id assigned (jfs, december 2003)

 script_name(english:"12Planet Chat Server Administration Authentication Cleartext Credential Disclosure");
 script_summary(english:"Checks for the data encapsulation of 12Planet Chat Server.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
a credential disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running 12Planet Chat Server, a web-based chat
server written in Java. It is, therefore, affected by a credential
disclosure vulnerability due to connections to this server being done
via cleartext. A man-in-the-middle attacker can exploit this
vulnerability to obtain the administrator password of the website and
use it to gain unauthorized access to this chat server.");
 # http://web.archive.org/web/20050209090944/http://cirt.dk/advisories/cirt-14-advisory.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f7511d2" );
 script_set_attribute(attribute:"solution", value:
"Add an HTTPS layer to the administration console for the deployment of
production servers.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/11");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:12planet:chat_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 
 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);
foreach port (ports)
{
 if(get_port_state(port))
 {
  res = http_get_cache(port:port, item:"/");
  if(res != NULL && "one2planet.tools.PSDynPage" >< res)
  {
    if(get_port_transport(port) == ENCAPS_IP)
    {
      report = "The remote 12Planet Chat Server administration login on port " + port + " supports unencrypted authentication.";
      set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);
      security_warning(port); exit(0);
    }
  }
 }
}
