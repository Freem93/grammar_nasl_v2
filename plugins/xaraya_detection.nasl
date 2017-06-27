#
# Script by Josh Zlatin-Amishav GPLv2
#
# Changes by Tenable:
# - Revised plugin title (12/30/2008)

include("compat.inc");

if(description)
{
 script_id(19426);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2013/01/11 22:59:17 $");
 
 script_name(english:"Xaraya Software/Version Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application framework written in
PHP." );
 script_set_attribute(attribute:"description", value:
"This script detects whether the remote host is running Xaraya and
extracts the version number and location if found.

Xaraya is an extensible, open source web application framework written
in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.xaraya.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:xaraya:xaraya");
script_end_attributes();

 
 summary["english"] = "Xaraya detection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Copyright (C) 2005-2013 Josh Zlatin-Amishav");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port)) exit(0);


if (thorough_tests) dirs = list_uniq(make_list("/xaraya", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 #display("res[", res, "]\n");
 if (isnull(res)) exit(0);

 if (
   # Cookie from Xaraya
   "^Set-Cookie: XARAYASID=" >< res ||
   # Meta tag from Xaraya
   "^X-Meta-Generator: Xaraya ::" >< res ||
   # Xaraya look-and-feel
   egrep(string:res, pattern:'div class="xar-(alt|block-.+|menu-.+|norm)"')
 ) {
   if (dir == "") dir = "/";

   # Look for the version number in a meta tag.
   pat = 'meta name="Generator" content="Xaraya :: ([^"]+)';
   matches = egrep(pattern:pat, string:res);
   if (matches) {
     foreach match (split(matches))
     {
       ver = eregmatch(pattern:pat, string:match);
       if (!isnull(ver))
       {
         ver = ver[1];
         info = '
Xaraya version ' + ver + ' is installed on the remote host
under the path ' + dir + '.
';
         break;
       }
     }
   }

   if (isnull(ver))
   {
     ver = "unknown";
     info = '
An unknown version of Xaraya is installed on the remote host
under the path ' + dir + '.
';
   }

   set_kb_item(
     name:string("www/", port, "/xaraya"),
     value:string(ver, " under ", dir)
   );
   set_kb_item(name:"www/xaraya", value: TRUE);
   security_note(port:port, extra:info);

   exit(0);
  }
}
