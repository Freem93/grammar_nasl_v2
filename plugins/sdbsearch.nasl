#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10720); 
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-1130");
 script_osvdb_id(598);
 
 script_name(english:"SuSE Support Data Base sbsearch.cgi Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"SuSE CGI 'sdbsearch.cgi' is installed.
This CGI allows a local (and possibly remote) user to execute arbitrary 
commands with the privileges of the HTTP server." );
 script_set_attribute(attribute:"solution", value:
"Modify the script so that it filters the HTTP_REFERRER variable, 
or delete it." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/08/02");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines the presence of the sdbsearch.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (make_list("", cgi_dirs()))
{
 r = http_send_recv3(method: "GET", port: port, item: dir + "/sdbsearch.cgi?stichwort=anything", 
  exit_on_fail: 1,
  add_headers:
    make_array("Referer", build_url(port: port, host: get_host_name(), qs: "/../../../../etc")));

 if("htdocs//../../../../etc/keylist.txt" >< r[1]+r[2])
 {
   security_hole(port);
   break;
 }
}
