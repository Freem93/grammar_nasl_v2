#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11359);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(7051);
 script_osvdb_id(53382);
 
 script_name(english:"Upload Lite upload.cgi Arbitrary File Upload");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that may allow arbitrary
uploads." );
 script_set_attribute(attribute:"description", value:
"The Upload Lite (upload.cgi) CGI script is installed.  This script has
a well-known security flaw that lets anyone upload arbitrary files on
the remote web server. 

Note that Nessus did not test whether uploads are possible, only that
the script exists." );
 script_set_attribute(attribute:"solution", value:
"Remove the affected script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/12");
 script_cvs_date("$Date: 2011/03/14 21:48:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of upload.cgi");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

found_files = "";
foreach d ( cgi_dirs() )
{
 loc = string(d, "/upload.cgi");
 r = http_send_recv3(method:"GET", item:loc, port:port);
 if (isnull(r)) exit(0);
 res = r[2];

 if(
  "<title>PerlScriptsJavascript.com " >< res &&
  "This script must be called" >< res
 ){
  found_files = string(found_files, "  ", loc, "\n");
  if (!thorough_tests) break;
 }
}

if (found_files != ""){
 report = string(
  "The Upload Lite CGI was found at the following locations :\n",
  "\n",
  "  ", found_files
 );
 security_hole(port:port, extra:report);
 exit(0);
}

