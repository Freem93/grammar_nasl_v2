#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87241);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/29 19:06:02 $");

  script_cve_id("CVE-2015-5168", "CVE-2015-5206");
  script_osvdb_id(128878, 128879);

  script_name(english:"Apache Traffic Server 5.3.x < 5.3.2 HTTP2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Apache Traffic Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote caching server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache Traffic Server running
on the remote host is 5.3.x prior to 5.3.2. It is, therefore, affected
by multiple vulnerabilities related to improper handling of HTTP/2
requests. An attacker can exploit these vulnerabilities to have an
unspecified impact. No further details are available.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://mail-archives.us.apache.org/mod_mbox/www-announce/201509.mbox/%3CCABF6JR2j5vesvnjbm6sDPB_zAGj3kNgzzHEpLUh6dWG6t8mC2w@mail.gmail.com%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4d47415");
  # https://issues.apache.org/jira/secure/ReleaseNote.jspa?version=12327092&projectId=12310963
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b450befb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Traffic Server version 5.3.2 or later.
Alternatively, disable HTTP/2 support.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("apache_traffic_server_version.nasl", "npn_protocol_enumeration.nasl");
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
version   = get_kb_item_or_exit('www/'+port+'/apache_traffic_server/version', exit_code:1);
source    = get_kb_item_or_exit('www/'+port+'/apache_traffic_server/source', exit_code:1);

# Currently ATS only supports NPN, not ALPN and does not support h2c
npnprotos = get_kb_list('SSL/NPN/'+port);
http2sup  = FALSE;
foreach proto (npnprotos)
{
  if(proto =~ '^h2')
  {
    http2sup = TRUE;
    break;
  }
}
if(!http2sup)
  exit(0, "The instance of "+app+" listening on port "+port+" does not appear to support HTTP/2 via SSL with the NPN extension.");

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

#Versions 5.3.0 and 5.3.1 are vulnerable
if (
  (ver[0] == 5 && ver[1] == 3 && ver[2] == 0) ||
  (ver[0] == 5 && ver[1] == 3 && ver[2] == 1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.3.2' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
