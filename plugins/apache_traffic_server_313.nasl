#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58593);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/08/04 20:57:14 $");

  script_cve_id("CVE-2012-0256");
  script_bugtraq_id(52696);
  script_osvdb_id(80571);

  script_name(english:"Apache Traffic Server 3.0.x < 3.0.4 / 3.1.x < 3.1.3 Host HTTP Header Parsing Remote Overflow");
  script_summary(english:"Checks the version of Apache Traffic Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote caching server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache Traffic Server
running on the remote host is 3.0.x prior to 3.0.4 or 3.1.x prior to
3.1.3. It is, therefore, affected by a heap-based buffer overflow
vulnerability when handling malicious HTTP host headers. A remote,
unauthenticated attacker can exploit this to execute arbitrary code on
the remote host subject to the privileges of the user running the
affected application.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://web.archive.org/web/20120531220750/https://www.cert.fi/en/reports/2012/vulnerability612884.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e58ea94c");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Mar/260");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Traffic Server 3.0.4 / 3.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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
source = get_kb_item_or_exit('www/'+port+'/apache_traffic_server/source', exit_code:1);

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 2) ||
  (ver[0] == 2 && ver[1] < 2) ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 4) ||
  (ver[0] == 3 && ver[1] == 1 && ver[2] < 3)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.0.4 / 3.1.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
