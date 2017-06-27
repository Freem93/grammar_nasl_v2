#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32325);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2008-2271");
  script_bugtraq_id(29242);
  script_osvdb_id(45170);
  script_xref(name:"Secunia", value:"30257");

  script_name(english:"Site Documentation Module for Drupal Database Tables Access Content Permission Information Disclosure");
  script_summary(english:"Retrieves info from the users table.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Site Documentation third-party module for Drupal
installed on the remote host allows any user with 'access content'
permission to retrieve the contents of arbitrary tables in the
application's database. An attacker can exploit this issue to retrieve
sensitive information, such as usernames, password hashes, email
addresses, and active SESSION IDs." );
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/258547");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Site Documentation 5.x-1.8 / 6.x-1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:site_documentation_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
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

# Grab info from a table.
#
# nb: "sessions" may also be of interest.
table = "users";

url = '/?q=sitedoc/table/'+table;
r = http_send_recv3(method: "GET", item:dir+url, port:port, exit_on_fail:TRUE);

# There's a problem if we see the table's contents.
if (
  (
    "Table Contents | " >< r[2] ||
    " Table Contents</h2>" >< r[2]
  ) &&
  'sort=desc&amp;order=' >< r[2] && 'tbody>' >< r[2]
)
{
  output = strstr(r[2], '<tbody>');
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
