#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54987);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_osvdb_id(72751);
  script_xref(name:"EDB-ID", value:"17365");

  script_name(english:"IBM Tivoli Management Framework Endpoint addr URL Default Credentials");
  script_summary(english:"Tries to access a protected page as tivoli:boss");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to authenticate to the remote server using the default
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Tivoli Endpoint installation is secured by default
credentials.  Nessus is able to make authenticated requests to '/addr'
by using the username 'tivoli' and password 'boss', which are
hard-coded in the server executable.

A remote, unauthenticated attacker could change the endpoint's
configuration or disable the web interface by using these default
credentials."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?931779eb");
  script_set_attribute(
    attribute:"solution",
    value:
"Disable the ability to change endpoint configuration from the browser
using the 'http_disable' configuration setting.  Refer to the IBM
documentation for more information."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Tivoli Endpoint Manager POST Query Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_management_framework");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("tivoli_endpoint_detect.nasl");
  script_require_keys("www/tivoli_endpoint");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:9495, embedded:TRUE);

install = get_install_from_kb(appname:'tivoli_endpoint', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = '/addr';
user = 'tivoli';
pass = 'boss';
auth_header = make_array('Authorization', 'Basic ' + base64(str:user + ':' + pass));

res = http_send_recv3(
  method:'POST',
  port:port,
  item:'/addr',
  exit_on_fail:TRUE,
  add_headers:auth_header
);

if ('Performing requested operation' >< res[2])
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to POST to the following URL using the default credentials';
    trailer =
      '  Username : ' + user + '\n' +
      '  Password : ' + pass;
    report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Tivoli Endpoint", build_url(qs:install['dir'], port:port));

