#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62989);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/01/08 17:10:53 $");

  script_name(english:"NetIQ Privileged User Manager Detection");
  script_summary(english:"Detects NetIQ Privileged User Manager web application");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web administration application for a
system that stores, manages, and delegates privileged user credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running NetIQ Privileged User Manager.  NetIQ
Privileged User Manager is an application for securely storing
credentials for privileged user accounts and delegating access to
network hosts and devices.");
  script_set_attribute(attribute:"see_also", value:"https://www.netiq.com/products/privileged-user-manager/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netiq:privileged_user_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# app runs on port 443 by default, but can be configured to run on port 80
port = get_http_port(default:80);

appname = "NetIQ Privileged User Manager";
kb_appname = "netiq_pum";

init_cookiejar();

# Start with a GET request to make sure we're looking at the proper service before sending POST requests
res = http_send_recv3(
  method:'GET',
  item:'/',
  port:port,
  exit_on_fail:TRUE
);

# Exit unless we are looking at correct application
if (
  isnull(res[2]) || 
  "<title>NetIQ Privileged User Manager</title>" >!< res[2] ||
  "Base.swf" >!< res[2]
) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# AMF encoded request to get version information (sent when loading 'about.swf')
# It returns a lot of data (including license information), but we are only interested in the version
# number ("vmr" field) which is sent as a string and service name ("svc" field) which is also sent as a 
# string
postdata = raw_string(
                                     0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x13,0x53, # //      . .......S
  0x50,0x46,0x2e,0x55,0x74,0x69,0x6c,0x2e,0x63,0x61,0x6c,0x6c,0x4d,0x6f,0x64,0x75, # // PF.Util. callModu
  0x6c,0x65,0x00,0x02,0x2f,0x31,0x00,0x00,0x00,0x40,0x0a,0x00,0x00,0x00,0x01,0x03, # // le../1.. .@......
  0x00,0x03,0x70,0x6b,0x74,0x03,0x00,0x06,0x6d,0x65,0x74,0x68,0x6f,0x64,0x02,0x00, # // ..pkt... method..
  0x0a,0x67,0x65,0x74,0x4c,0x69,0x63,0x65,0x6e,0x73,0x65,0x00,0x06,0x6d,0x6f,0x64, # // .getLice nse..mod
  0x75,0x6c,0x65,0x02,0x00,0x08,0x72,0x65,0x67,0x69,0x73,0x74,0x72,0x79,0x00,0x03, # // ule...re gistry..
  0x75,0x69,0x64,0x06,0x00,0x00,0x09,0x00,0x00,0x09,0x00,0x13,0x53,0x50,0x46,0x2e, # // uid..... ....SPF.
  0x55,0x74,0x69,0x6c,0x2e,0x67,0x65,0x74,0x56,0x65,0x72,0x73,0x69,0x6f,0x6e,0x00, # // Util.get Version.
  0x02,0x2f,0x32,0x00,0x00,0x00,0x14,0x0a,0x00,0x00,0x00,0x01,0x03,0x00,0x08,0x69, # // ./2..... .......i
  0x64,0x65,0x6e,0x74,0x69,0x74,0x79,0x06,0x00,0x00,0x09                           # // dentity. ...
);

res = http_send_recv3(
  method:'POST',
  item:'/',
  port:port,
  add_headers:make_array(
    'Content-Type', 'application/x-amf', # required
    'x-flash-version', '11,4,402,278'
  ),
  data:postdata, 
  exit_on_fail:TRUE
);

version = UNKNOWN_VER;

# try to parse out version 
vrm_search = raw_string(
               0x00, 0x03, # length
               0x76, 0x72, 0x6d, # "vrm"
               0x02 # string is next
             );

pos = stridx(res[2], vrm_search);

if (vrm_search >< res[2] && pos >= 0)
{
  len = getword(blob:res[2], pos:pos+strlen(vrm_search));
  if (len == NULL) exit(1, "The response from port "+port+" is not long enough to contain the length of a version string.");

  if (strlen(res[2]) <  pos + strlen(vrm_search) + 2 + len) exit(1, "The response from port "+port+" is not long enough to contain a version string.");

  version = substr(res[2], pos + strlen(vrm_search) + 2, pos + strlen(vrm_search) + 2 + len - 1);  
}

# try to parse out service name
svc_str = '';

svc_search = raw_string(
               0x00, 0x03, # length
               0x73, 0x76, 0x63, # "svc"
               0x02 # string is next
             );

if(svc_search >< res[2])

pos = stridx(res[2], svc_search);

if(svc_search >< res[2] && pos && !isnull(pos))
{
  len = getword(blob:res[2], pos: pos + strlen(svc_search));
  if(len == NULL)
    exit(1, 'The response is not long enough to contain length of service string.');

  if(strlen(res[2]) <  pos + strlen(svc_search) + 2 + len)
    exit(1, 'The response is not long enough to contain service string.');

  svc_str = substr(res[2], pos + strlen(svc_search) + 2, pos + strlen(svc_search) + 2 + len - 1);  
  set_kb_item(name:"www/" + port + "/" + kb_appname + "/svc_str", value:svc_str);
}

post_data = 
  raw_string (0x00, 0x00, 0x00, 0x00, 0x00, 0x01) +
  raw_string(0x00,0x13) + # len
  "SPF.Util.callModule" +
  raw_string(0x00, 0x03, 0x2f, 0x33, 0x30, 0x00, 0x00, 
             0x02, 0x16, 0x0a, 0x00, 0x00, 0x00, 0x01) +
  raw_string(0x03) + # obj
  raw_string(0x00, 0x03) + #len
  "pkt" +
  raw_string(0x03) + # obj 
  raw_string(0x00, 0x06) + # len
  "Engine" +
  raw_string(0x03) + # obj
  raw_string(0x00, 0x00, 0x09) + # end obj
  raw_string(0x00, 0x05) + # len
  "Patch" +
  raw_string(0x03) + # obj
  raw_string(0x00, 0x00, 0x09) + # end obj
  raw_string(0x00, 0x06) + # len
  "Module" +  
  raw_string(0x03) + # obj
  raw_string(0x00, 0x00, 0x09) + # end obj
  raw_string(0x00, 0x07) + # len
  "Console" +
  raw_string(0x03) + # obj
  raw_string(0x00, 0x00, 0x09) + # end obj
  raw_string(0x00, 0x06) + # len
  "method" +
  raw_string(0x02) + # str
  raw_string(0x00, 0x0c) + # len 
  "listPackages" + 
  raw_string(0x00, 0x06) + # len
  "module" + 
  raw_string(0x02) + # str
  raw_string(0x00, 0x06) + # len
  "pkgman" + 
  raw_string(0x00, 0x00, 0x09) + # end obj
  raw_string(0x00, 0x00, 0x09); # end obj

res = http_send_recv3(
  method:'POST',
  item:'/Base.swf',
  port:port,
  add_headers:make_array(
    'Content-Type', 'application/x-amf', # required
    'x-flash-version', '11,4,402,278'
  ),
  data:post_data, 
  exit_on_fail:TRUE
);

cur_pos = 0;

package_search = raw_string(
                   0x00, 0x05, # length
                   0x54, 0x69, 0x74, 0x6c, 0x65, # 'Title'
                   0x03, # obj
                   0x00, 0x07,
                   0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, # 'Content'                  
                   0x02 # str next
);

version_search = raw_string(
                   0x00, 0x07, # length 
                   0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, # 'version'
                   0x02 # str next
);

pos = stridx(res[2], package_search);
package_version = make_array();

# the default configuration of this software allows package information to be
# retrieved without authentication via the 'listPackages' method
while(pos != -1 &&
      version_search >< res[2] &&
      package_search >< res[2])
{
  package_title = '';
  if(pos != -1) 
  {
    len = getword(blob:res[2], pos: pos + strlen(package_search));
    if(len == NULL)
      continue;
    if(strlen(res[2]) <  pos + strlen(package_search) + 2 + len)
     continue;
    
    package_title = substr(res[2], pos + strlen(package_search) + 2, pos + strlen(package_search) + 2 + len - 1);  
   
    cur_pos = pos + strlen(package_search) + 2 + len;

    pos_ver = stridx(res[2], version_search, cur_pos);
    if(pos_ver == -1)
      continue;

    len = getword(blob:res[2], pos: pos_ver + strlen(version_search));
    if(len == NULL)
      continue;
    if(strlen(res[2]) <  pos_ver + strlen(version_search) + 2 + len)
      continue;

    # grab version info and convert to x.x.x.x format rather than x,x,x,x
    pkg_version = substr(res[2], pos_ver + strlen(version_search) + 2, pos_ver + strlen(version_search) + 2 + len - 1);
    pkg_version = str_replace(string:pkg_version, find: ',', replace: '.');
    # we are might have to use the version info in ver_compare, so make sure it is the correct format
    if(pkg_version !~ "^[0-9][0-9.]+[0-9]$")
      continue;    

    if(!isnull(package_version[package_title]))
    {
      # versions for same title should all be the same, but just in case, use the latest
      if(ver_compare(ver:package_version[package_title], fix:pkg_version, strict:FALSE) == -1)
        package_version[package_title] = pkg_version;
    }
    else
      package_version[package_title] = pkg_version;
      
    pos = stridx(res[2], package_search, cur_pos);
  }
}

module_info = '';

foreach package (keys(package_version))
{
  # reformat package title
  package_title = tolower(package);
  package_title = str_replace(string:package_title, find:' ', replace: '_');

  # reformat
  temp_arr = split(package_version[package], sep:'.' , keep:FALSE); 
  if(max_index(temp_arr) < 5 && max_index(temp_arr) > 3)
  { 
    pkg_str_version = temp_arr[0] + '.' + temp_arr[1] + '.' + temp_arr[2];
    if(max_index(temp_arr) == 4)
      pkg_str_version += ('-' + temp_arr[3]);
  }
  else
    pkg_str_version = pkg_version;

  set_kb_item(name:"www/" + port + "/" + kb_appname + "/packages/" + package_title, value:package_version[package]);
  module_info += '\n    Name    : ' + package +
                 '\n    Version : ' + pkg_str_version + '\n';
}
# Register install
installs = add_install(
  installs:NULL,
  ver:version,
  dir:'/',
  appname:kb_appname,
  port:port
);

if (report_verbosity > 0)
{

  report = '\n  URL     : ' + build_url(qs:'/', port:port) +
           '\n  Version : ' + version;
  if(module_info != '')
    report += '\n\n  Installed Packages : ' + module_info;
  security_note(port:port, extra:report);
}
else security_note(port);
