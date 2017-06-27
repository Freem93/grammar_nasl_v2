#
# This script was written by Javier Fernandez-Sanguino Pena <jfs@computer.org>
# based on scripts made by Renaud Deraison <deraison@cvs.nessus.org>
#
# Slightly modified by rd to do pattern matching.
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (3/27/2009)
#


include("compat.inc");

if(description)
{
 script_id(10781);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-2001-0660");
 script_bugtraq_id(3301);
 script_osvdb_id(626);
 
 script_name(english:"Microsoft Outlook Web Access (OWA) Anonymous Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"It is possible to browse the information of the OWA server by accessing as an
anonymous user with the following URL:

http://www.example.com/exchange/root.asp?acs=anon

After this access, the anonymous user can search for valid users in the OWA 
server and can enumerate all users by accessing the following URL:

http://www.example.com/exchange/finduser/details.asp?obj=XXX
(where XXX is a string of 65 hexadecimal numbers)

Data that can be accessed by an anonymous user
may include: usernames, server names, email name accounts,
phone numbers, departments, office, management relationships...

This information will help an attacker to make social
engineering attacks with the knowledge gained. This attack
can be easily automated since, even if direct access to search
is not possible, you only need the cookie given on the anonymous
login access.

Administrators might be interested in consulting
the following URL:

http://web.archive.org/web/20030805172512/http://support.microsoft.com/support/exchange/content/whitepapers/owaguide.doc" );
 script_set_attribute(attribute:"solution", value:
"	Disable anonymous access to OWA. Follow these steps:
	1. In Microsoft Exchange Administrator open the Configuration container.
	2. Choose Protocols, and then double-click HTTP (Web) Site Settings
	3. Unselect the 'Allow anonymous users to access 
	the anonymous public folders' check box.
	4. Select the Folder Shortcuts tab.
	5. Remove all folders which are allowed anonymous viewing.
        6. Choose OK.
	7. Remove the anonymous access from the login web pages." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/10/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/09/06");
 script_cvs_date("$Date: 2016/05/26 16:04:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Outlook Web anonymous access";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Javier Fernandez-Sanguino Pena");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if ( ! can_host_asp(port:port) ) exit(0);





 cgi = "/exchange/root.asp?acs=anon";
 if(is_cgi_installed_ka(item:cgi, port:port))
 {
  soc = http_open_socket(port);
  if ( ! soc ) audit(AUDIT_PORT_CLOSED, port, "TCP");
  req = http_get(item:"/exchange/root.asp?acs=anon", port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if ("/exchange/logonfrm.asp" >< r)
  {
   soc = http_open_socket(port);
   if ( ! soc ) audit(AUDIT_PORT_CLOSED, port, "TCP");
   req = http_get(item:"/exchange/logonfrm.asp", port:port);
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);

   if (!("This page has been disabled" >< r))
   {
    security_warning(port);
   }
  }
 }
