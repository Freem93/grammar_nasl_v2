#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39365);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2009-2035");
  script_bugtraq_id(35292);
  script_osvdb_id(54999);
  script_xref(name:"Secunia", value:"33371");

  script_name(english:"Drupal SA-CONTRIB-2009-036: Services Module Key-Based Access Bypass");
  script_summary(english:"Attempts to access form to add a key.");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an authentication bypass vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of Drupal running on the remote host includes the
third-party Services module, which offers a way to integrate external
applications with Drupal using XMLRPC, SOAP, REST, AMF, or other such
interfaces. It is currently configured to use a validation token, or
'key', for authentication, and contains a flaw that allows an
unauthenticated, remote attacker to view or add keys. Depending on
access control checks for the underlying services exposed, an attacker
may be able to access services that he would not normally be able to.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/488004");
  script_set_attribute(attribute:"solution", value:"Upgrade to Services 6.x-0.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:services_module_for_drupal");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
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

# Try to pull up form for adding a key.
url = "/admin/build/services/keys/add";

res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

# There's a problem if we see the expected contents.
if (
  'id="services-admin-keys-form"' >< res[2] ||
  'id="edit-submit" value="Create key"' >< res[2]
)
{
  output = strstr(res[2], 'id="services-admin-keys-form"');
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
