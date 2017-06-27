#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70586);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/11/19 17:31:36 $");

  script_bugtraq_id(63267);
  script_osvdb_id(98827);

  script_name(english:"IBM Tivoli Endpoint Manager Server 9.0.777 (patch 2) LDAP and AD Authentication");
  script_summary(english:"Checks the version of the Tivoli Endpoint Manager Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication-related
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IBM Tivoli Endpoint Manager
Server 9.0.777.0 (patch 2) is installed on the remote host. It is,
therefore, affected by a vulnerability that could allow an attacker to
impersonate any LDAP-authenticated Console user when LDAP and Active
Directory authentication is enabled.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21652193");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Endpoint Manager Server 9.0.787 (patch 4) or later
or disable LDAP and Active Directory authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("www/BigFixHTTPServer", "Settings/ParanoidReport");
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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version != '9.0.777.0') audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

if (report_verbosity > 0)
{
  report = "";

  source = get_kb_item("www/BigFixHTTPServer/"+port+"/source");
  if (!isnull(source))
    report += '\n  Source            : ' + source;

  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 9.0.787.0' +
    '\n';

  security_warning(port:port, extra:report);
}
else security_warning(port);
