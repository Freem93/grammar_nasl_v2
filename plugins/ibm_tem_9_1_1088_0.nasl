#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79334);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id("CVE-2014-3066");
  script_osvdb_id(108604);

  script_name(english:"IBM Tivoli Endpoint Manager Server 8.2.x < 8.2.1445.0 / 9.0.x < 9.0.853.0 / 9.1.x < 9.1.1088.0 Unspecified XXE File Disclosure");
  script_summary(english:"Checks the version of Tivoli Endpoint Manager Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a file disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM Tivoli Endpoint
Manager server installed on the remote host is 8.2.x prior to
8.2.1445.0, 9.0.x prior to 9.0.853.0, or 9.1.x prior to 9.1.1088.0. It
is, therefore, affected by an information disclosure vulnerability due
to an XML External Entity (XXE) flaw that allows an attacker to read
arbitrary files on the host by sending specially crafted XML data.

Note that this vulnerability only affects the Console, Root Server,
Web Reports, and Server API components. It does not affect the Agent
and Relay components.");
  # 8.2
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673961");
  # 9.0
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673964");
  # 9.1
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673967");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Endpoint Manager server 8.2.1445.0 / 9.0.853.0 /
9.1.1088.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("Settings/ParanoidReport","www/BigFixHTTPServer");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

# Only affects the Root Server, Web Server and API NOT Relays or End Point Agents
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "IBM Tivoli Endpoint Manager";
port = get_http_port(default:52311, embedded:FALSE);

version = get_kb_item_or_exit("www/BigFixHTTPServer/"+port+"/version");
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);
if (version !~ "^(\d+\.){2,}\d+$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

if (version =~ "^8\.2\." && ver_compare(ver:version, fix:"8.2.1445.0", strict:FALSE) < 0)
  fix = "8.2.1445.0";
else if (version =~ "^9\.0\." && ver_compare(ver:version, fix:"9.0.853.0", strict:FALSE) < 0)
  fix = "9.0.853.0";
else if (version =~ "^9\.1\." && ver_compare(ver:version, fix:"9.1.1088.0", strict:FALSE) < 0)
  fix = "9.1.1088.0";
else
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

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
