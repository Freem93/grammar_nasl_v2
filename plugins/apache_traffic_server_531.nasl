#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87240);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id("CVE-2015-3249");
  script_osvdb_id(128881, 128882);

  script_name(english:"Apache Traffic Server 5.3.x < 5.3.1 'url_sig' Plugin Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Apache Traffic Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote caching server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache Traffic Server running
on the remote host is 5.3.x prior to 5.3.1. It is, therefore, affected
by multiple vulnerabilities related to the 'url_sig' plugin :

  - An out-of-bounds access error exists that is triggered
    when handling a specially crafted HTTP request. An
    unauthenticated, remote attacker can exploit this to
    crash the server. (VulnDB 128881)

  - A security bypass vulnerability exists due to a flaw
    that is triggered when handling empty secret key URLs.
    An unauthenticated, remote attacker can exploit this to
    bypass validation mechanisms, thereby gaining access to
    protected assets. (VulnDB 128882)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://issues.apache.org/jira/secure/ReleaseNote.jspa?version=12327092&projectId=12310963
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b450befb");
  # http://mail-archives.us.apache.org/mod_mbox/www-announce/201507.mbox/%3CCABF6JR37mWzDmXDqRQwRUXiojBZrhidndnsY1ZgmcZv-o7-a+g@mail.gmail.com%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c77e9f28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Traffic Server version 5.3.1 or later.
Alternatively, disable the 'url_sig' plugin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("apache_traffic_server_version.nasl");
  script_require_keys("www/apache_traffic_server","Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Requires use and configuration of the url_sig plugin
# which is still classified as "experimental"
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Apache Traffic Server';
port = get_http_port(default:8080);

# Make sure this is Apache Traffic Server
get_kb_item_or_exit('www/'+port+'/apache_traffic_server');

# Check if we could get a version
version   = get_kb_item_or_exit('www/'+port+'/apache_traffic_server/version', exit_code:1);
source    = get_kb_item_or_exit('www/'+port+'/apache_traffic_server/source', exit_code:1);

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

#Version 5.3.0 is vulnerable
if ((ver[0] == 5 && ver[1] == 3 && ver[2] == 0))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.3.1' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
