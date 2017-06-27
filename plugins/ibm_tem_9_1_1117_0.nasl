#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79335);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_osvdb_id(107729);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"IBM Tivoli Endpoint Manager Server 9.1.x < 9.1.1117.0 OpenSSL Security Bypass");
  script_summary(english:"Checks the version of the Tivoli Endpoint Manager Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM Tivoli Endpoint
Manager Server installed on the remote host uses a vulnerable OpenSSL
library that contains a flaw in the processing of ChangeCipherSpec
messages. The flaw allows an attacker to cause usage of weak keying
material leading to simplified man-in-the-middle attacks.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21677842");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Tivoli Endpoint Manager Server 9.1.1117.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("www/BigFixHTTPServer");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "IBM Tivoli Endpoint Manager";
port = get_http_port(default:52311, embedded:FALSE);

version = get_kb_item_or_exit("www/BigFixHTTPServer/"+port+"/version");
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);
if (version !~ "^(\d+\.){2,}\d+$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = "9.1.1117.0";

if (
  version =~ "^9\.1\.1065($|[^0-9])" ||
  version =~ "^9\.1\.1082($|[^0-9])" ||
  version =~ "^9\.1\.1088($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report = "";

    source = get_kb_item("www/BigFixHTTPServer/"+port+"/source");
    if (!isnull(source))
      report += '\n  Source            : ' + source;

    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
