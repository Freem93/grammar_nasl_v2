#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(21293);
 script_version ("$Revision: 1.13 $");

 script_cve_id("CVE-2006-2072");
 script_bugtraq_id(17691);
 script_osvdb_id(57053);

 script_name(english:"DeleGate DNS Response Message DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"A rogue DNS server may crash the remote proxy." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Delegate, a multi-application proxy.

The remote version of this software is vulnerable to a denial of service
when processing invalid DNS responses. An attacker may exploit this flaw to
disable this service remotely.

To exploit this flaw, an attacker would need to be able to inject malformed
DNS responses to the queries sent by the remote application." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to DeleGate 8.11.6 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/25");
 script_cvs_date("$Date: 2011/03/21 16:24:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Detetermines the version of the remote DeleGate proxy"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
 script_family(english:"Firewalls"); 
 script_dependencie("http_version.nasl");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("Services/www");
if(!port) port = 8080;

if(get_port_state(port))
{
   banner = get_http_banner(port:port);
   if ( banner && "DeleGate/" >< banner )
   {
   serv = egrep(string:banner, pattern:"^Server:");
   if(ereg(pattern:"^Server:.*DeleGate/[0-7]\.|8\.([0-9]\.|10\.|11\.[0-5][^0-9])", string:serv, icase:TRUE)) security_warning(port);
   }
}
