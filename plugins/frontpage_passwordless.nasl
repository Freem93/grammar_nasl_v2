#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11455);
 script_version ("$Revision: 1.21 $");

 script_name(english:"Microsoft FrontPage Unpassworded Installation");
 script_summary(english:"Determines if the remote web server is password protected");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server is configured insecurely."
 );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to have FrontPage Extensions installed
with incorrectly set permissions.  A remote attacker could exploit
this to modify web pages on the server." );
  # http://web.archive.org/web/20080103161410/http://www.ciac.org/ciac/bulletins/k-048.shtml
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?da14142c"
 );
 script_set_attribute(attribute:"solution", value:
"If FrontPage is being used to administer the website, tighten the
permissions.  If not, remove the _vti_* directories and _vti_inf.html.
Refer to the advisory for more information." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/04");
 script_cvs_date("$Date: 2012/09/21 23:21:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl", "no404.nasl");
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

dirs = get_kb_list(string("www/", port, "/content/directories"));
if(!isnull(dirs))dirs = make_list("", dirs);
else dirs = make_list(cgi_dirs());

unpassworded = NULL;

foreach dir (dirs)
{ 
 url = string(dir, "/_vti_inf.html");
 res = http_send_recv3(method:"GET", item:url, port:port); 
 if (isnull(res)) exit(0);

 if("FPAuthorScriptUrl" ><  res[2])
 {
  str = egrep(pattern:"FPAuthorScriptUrl", string:res[2]);
  auth = ereg_replace(pattern:'.*FPAuthorScriptUrl="([^"]*)".*', string:str, replace:"\1");
  content = "method=open+service%3a5%2e0%2e2%2e2623&service%5fname=" + str_replace(string:dir, find:"/", replace:"%2f");
 
  header = make_array(
    "MIME-Version", "1.0",
    "Host", get_host_name(),
    "User-Agent", "MSFrontPage/5.0",
    "Accept", "auth/sicily",
    "Content-Type", "application/x-www-form-urlencoded",
    "X-Vermeer-Content-Type", "application/x-www-form-urlencoded"
  );
  url2 = string(dir, "/", auth);
  res = http_send_recv3(
    method:"POST",
    item:url2,
    port:port,
    add_headers:header,
    data:content
  );

  if(
    egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res[2]) &&
    "x-vermeer-rpc" >< res[2] &&
    "status=917592" >!< res[2] &&
    "status=917656" >!< res[2]
  ) 
  {
   if (dir == "") dir = "/"; 
   unpassworded += dir + '\n'; 
  }
 }
}

if(!isnull(unpassworded))
{
 report = "
The following directories have FrontPage Extensions enabled, but are not
password protected :

" + unpassworded + "

Anyone can use Microsoft FrontPage to modify them.
";

 security_hole(port:port, extra:report);
}
