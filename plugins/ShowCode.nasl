#
# ShowCode ASP
#
# This plugin was written in C by Immo Goltz <Immo.Goltz@gecits-eu.com>
# and is released under the GPL
#
# - Description taken from  http://www.nessus.org/u?16ba761f
#
# Converted in NASL by Renaud Deraison <deraison@cvs.nessus.org>

# Changes by Tenable:
# - Converted in NASL  (RD)
# - Revised plugin title, desc formatting (4/3/2009)
# - Updated to use compat.inc (11/20/2009)

include("compat.inc");

if(description)
{
 script_id(10007);
 script_version ("$Revision: 1.38 $");
 script_cve_id("CVE-1999-0736");
 script_bugtraq_id(167);
 script_osvdb_id(7);

 script_name(english:"Microsoft IIS / Site Server showcode.asp source Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to read arbitrary files on the remote host." );
 script_set_attribute(attribute:"description", value:
"Internet Information Server (IIS) 4.0 ships with a set of sample files to
help web developers learn about Active Server Pages (ASP). One of these
sample files, 'showcode.asp' (installed in /msadc/Samples/SELECTOR/), is
designed to view the source code of the sample applications via a web
browser.

The 'showcode.asp' file does inadequate security checking and allows anyone
with a web browser to view the contents of any text file on the web server.
This includes files that are outside of the document root of the web server.

The 'showcode.asp' file is installed by default at the URL:
http://www.YOURSERVER.com/msadc/Samples/SELECTOR/showcode.asp
It takes 1 argument in the URL, which is the file to view.
The format of this argument is: source=/path/filename

This is a fairly dangerous sample file since it can view the contents of any 
other files on the system. The author of the ASP file added a security check to 
only allow viewing of the sample files which were in the '/msadc' directory on 
the system. The problem is the security check does not test for the '..'
characters within the URL. The only checking done is if the URL contains the
string '/msadc/'. This allows URLs to be created that view, not only files
outside of the samples directory, but files anywhere on the entire file
system that the web server's document root is on." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16ba761f" );
 script_set_attribute(attribute:"solution", value:
"For production servers, sample files should never be installed, so
delete the entire /msadc/samples directory. If you must have the
'showcode.asp' capability on a development server, the 'showcode.asp' file 
should be modified to test for URLs with '..' in them and deny those requests." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/07/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/05/07");
 script_cvs_date("$Date: 2011/03/11 21:52:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines the presence of showcode.asp");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2011 Immo Goltz <Immo.Goltz@gecits-eu.com>");

 script_family(english:"CGI abuses");
 
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


cgi = string("/msadc/Samples/SELECTOR/showcode.asp");
if ( is_cgi_installed_ka(item:cgi, port:port) )
 {
  item = "/msadc/Samples/SELECTOR/showcode.asp?source=/msadc/Samples/../../../../../winnt/win.ini";
  req = http_get(item:item, port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   r = tolower(r);
   if("[fonts]"  >< r){
	security_hole(port);
	}
   exit(0);
  }
 }

  

