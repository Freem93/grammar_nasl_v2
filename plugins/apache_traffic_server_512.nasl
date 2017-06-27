#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(80919);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/04 20:57:14 $");

  script_cve_id("CVE-2014-10022");
  script_bugtraq_id(71879);
  script_osvdb_id(116747);

  script_name(english:"Apache Traffic Server 5.1.x < 5.1.2 DoS");
  script_summary(english:"Checks the version of Apache Traffic Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote caching server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache Traffic Server running
on the remote host is 5.1.x prior to 5.1.2. It is, therefore, affected
by a denial of service vulnerability caused by an flaw in the
'HttpTransact.cc' file related to an error in internal buffer sizing.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://cwiki.apache.org/confluence/display/TS/What%27s+new+in+v5.1.x
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7cd8218");
  # https://www.mail-archive.com/users%40trafficserver.apache.org/msg04314.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79fdc167");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Traffic Server 5.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

#Versions 5.1.0 and 5.1.1 are vulnerable
if (
  (ver[0] == 5 && ver[1] == 1 && ver[2] == 0) ||
  (ver[0] == 5 && ver[1] == 1 && ver[2] == 1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.1.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
