#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (4/28/09)
# - Rename DotNetNuke to DNN to reflect product name change
# - Add mention of DNN in solution.
# - Edit the code to get the new KB item being set by the detection plugin
# - add misc_func.inc for base64 code (10/13/15)

include("compat.inc");

if (description)
{
  script_id(18505);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/15 13:39:09 $");

  script_cve_id("CVE-2005-0040");
  script_bugtraq_id(13644, 13646, 13647);
  script_osvdb_id(16614, 16615, 16616);

  script_name(english:"DNN (DotNetNuke) < 3.0.12 Multiple XSS");
  script_summary(english:"Checks version of DNN.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an ASP application that is affected by
multiple input validation flaws.");
  script_set_attribute(attribute:"description", value:
"The remote host is running DNN, a portal written in ASP. 

The remote installation of DNN, according to its version number,
contains several input validation flaws leading to the execution of
attacker supplied HTML and script code.");
  script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/2005/May/197");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN version 3.0.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Copyright (C) 2005-2016 Josh Zlatin-Amishav");
  script_family(english:"CGI abuses : XSS");

  script_require_ports("Services/www", 80);
  script_dependencie("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  exit(0);
}

# the code!
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

get_kb_item_or_exit("installed_sw/DNN");
port = get_http_port(default:80);

if(!can_host_asp(port:port))exit(0, "The web server on port "+port+" does not support ASP");

installs = get_kb_list("installed_sw/"+port+"/DNN/*/version");
if (isnull(installs) || max_index(keys(installs)) == 0)
  exit(0, "Couldn't find KB item installed_sw/"+port+"/DNN");

dirs = make_list();
foreach install (keys(installs))
{
  match = eregmatch(string:install, pattern:"/DNN/(.+)/");

  if (!isnull(match[1]) || match[1] == '')
  {
    path = match[1];
    path = str_replace(string:path, find:'$', replace:'=');
    path = str_replace(string:path, find:'&', replace:'/');
    dir = base64_decode(str:path);
    dirs = make_list(dirs, dir);
  }
}

global_var port;

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/default.aspx", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( isnull(res) ) exit(1, "The web server on port "+port+" did not answer");

 if ( 'DotNetNukeAnonymous' >< res && egrep(pattern:"\( DNN (2\.0\.|2\.1\.[0-4]|3\.0\.([0-9]|1[0-1] \)))", string:res) )
 {
        security_warning(port);
        set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}

foreach dir (dirs)
{
  check(url:dir);
}
