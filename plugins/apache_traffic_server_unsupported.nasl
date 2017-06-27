#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80920);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/31 17:44:28 $");

  script_name(english:"Apache Traffic Server Unsupported");
  script_summary(english:"Checks the version of Apache Traffic Server.");

  script_set_attribute(attribute:"synopsis", value:
"The caching server running on the remote host is unsupported.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache Traffic Server running
on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://trafficserver.apache.org/");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/TS/Release+Management");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache Traffic Server that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("apache_traffic_server_version.nasl");
  script_require_keys("www/apache_traffic_server");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = 'Apache Traffic Server';
port = get_http_port(default:8080);

# Make sure this is Apache Traffic Server
get_kb_item_or_exit('www/'+port+'/apache_traffic_server');

# Check if we could get a version
version = get_kb_item_or_exit('www/'+port+'/apache_traffic_server/version', exit_code:1);
source  = get_kb_item_or_exit('www/'+port+'/apache_traffic_server/source', exit_code:1);

version_list = split(version, sep:'.');
major = int(version_list[0]);
minor = int(version_list[1]);

# Versions 6.2.x, 7.1.x and 8.x are the current supported versions
if (
    (major == 7 && minor < 1) ||
    (major == 6 && minor < 2) || # 6.2.x is supported until Dec 2017
    (major < 6)
)
{
  register_unsupported_product(
    product_name:app,
    cpe_base:"apache:traffic_server", version:version
  );

  report =
    '\n  Version source     : ' + source +
    '\n  Installed version  : ' + version +
    '\n  End of support URL : https://cwiki.apache.org/confluence/display/TS/Release+Management' +
    '\n  Supported versions : 6.2.x / 7.1.x / 8.x' +
    '\n';
    
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
