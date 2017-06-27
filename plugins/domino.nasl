#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if (description)
{
 script_id(10057);
 script_version("$Revision: 1.42 $");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");

 script_osvdb_id(49);

 script_name(english: "IBM Lotus Domino ?open Forced Directory Listing");
 script_summary(english: "Checks for the domino ?open feature");
 
 script_set_attribute(attribute:"synopsis", value:
"Databases can be browsed on the remote web server.");
 script_set_attribute(attribute:"description", value:
"It is possible to browse the remote web server directories by
appending '?open' to the end of the URL.  For example :

	http://www.example.com/?open

Data that can be accessed by unauthorized users may include usernames,
server names and IP addresses, dial-up server phone numbers,
administration logs, files names, and data files (including credit
card information, proprietary corporate data, and other information
stored in eCommerce related databases.) In some instances, it may be
possible for an unauthorized user to modify these files or perform
server administration functions via the web administration interface."
);
 script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/1/10820");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92723a64");
 script_set_attribute(attribute:"solution", value:
"Disable the database browsing. To do this :

    1. From the Domino Administrator, select the Configuration tab, and 
       open the Server document,

    2. Select Internet Protocols - HTTP tab,

    3. In the 'Allow HTTP clients to browse databases' field, choose No,

    4. Save the document.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/09");
 script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/21");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Lotus Domino" >!< sig ) exit(0);


banner = get_http_banner(port:port);
	
if(egrep(pattern:"Server:.*otus.*", string:banner))
{
 cgi = "/?open";
 ok = is_cgi_installed3(item:cgi, port:port);
 if(ok)security_warning(port);
}
