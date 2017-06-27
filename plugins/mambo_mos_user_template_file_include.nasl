#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33479);
  script_version("$Revision: 1.10 $");
  script_osvdb_id(48832);
  script_cvs_date("$Date: 2013/01/25 01:19:08 $");


  script_name(english:"Mambo < 4.6.5 mos_user_template Local File Inclusion");
  script_summary(english:"Tries to change mos_user_template cookie in Mambo");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Mambo installed on the remote host fails to properly
check user input to the 'mos_user_template' cookie for directory
traversal sequences before using it to include PHP code from a local
file.  An unauthenticated attacker may be able to exploit this issue
to view arbitrary files or to execute arbitrary PHP code on the
affected host." );
 script_set_attribute(attribute:"see_also", value:"http://source.mambo-foundation.org/content/view/144/1/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mambo 4.6.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/mambo_mos");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  set_http_cookie(name: "mos_user_template", value: "../administrator");
  rq = http_mk_get_req(item:string(dir, "/index.php"), port:port);
  erase_http_cookie(name: "mos_user_template");
  r = http_send_recv_req(port: port, req: rq);
  if (isnull(r)) exit(0);

  # There's a problem if we were able to set the cookie.
  if (get_http_cookie(name:"mos_user_template") == "\.\.%2Fadministrator%2F")
  {
    security_warning(port);
    exit(0);
  }
}
