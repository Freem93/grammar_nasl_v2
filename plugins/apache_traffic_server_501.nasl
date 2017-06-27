#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(80917);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/08/04 20:57:14 $");

  script_cve_id("CVE-2014-3525");
  script_bugtraq_id(69173);
  script_osvdb_id(110155);

  script_name(english:"Apache Traffic Server 4.x < 4.2.1.1 / 5.x < 5.0.1 Synthetic Health Check Vulnerability");
  script_summary(english:"Checks the version of Apache Traffic Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote caching server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache Traffic Server running
on the remote host is prior to 4.2.1.1 / 5.0.1. It is, therefore,
affected by an unspecified vulnerability related to synthetic health
checks.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://cwiki.apache.org/confluence/display/TS/What%27s+new+in+v5.1.x
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7cd8218");
  # https://www.mail-archive.com/users%40trafficserver.apache.org/msg04051.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9831e59");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Traffic Server 4.2.1.1 / 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/23");
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

fix = NULL;

# Vulnerable versions include everything below the fixed version
# At the time of this release, the 4.x branch is for LTS
# First check if version is in LTS branch
# Next, check if below patched
if ( ver[0] == 4)
{
  if (
    ver[1] < 2 || # 4.x < 4.2
    (ver[1] == 2 && ver[2] < 1) || # 4.2.x < 4.2.1
    (ver[1] == 2 && ver[2] == 1 && ver[3] < 1) # 4.2.1.x < 4.2.1.1
  )
  {
    fix = '4.2.1.1';
  }
}
else if ( ver[0] < 5 || (ver[0] == 5 && ver[1] == 0 && ver[2] < 1) )
  fix = '5.0.1';

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
