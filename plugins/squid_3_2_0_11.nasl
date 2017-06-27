#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56215);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id("CVE-2011-3205");
  script_bugtraq_id(49356);
  script_osvdb_id(74847);

  script_name(english:"Squid 3.x < 3.0.STABLE26 / 3.1.15 / 3.2.0.11 Gopher Buffer Overflow");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:"The remote proxy server is affected by a buffer overflow.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 3.x prior to 3.0.STABLE26 / 3.1.15 / 3.2.0.11. It reportedly
contains a buffer overflow when parsing responses from Gopher servers
that results in memory corruption and usually causes the Squid server
itself to crash.

Note that Nessus has relied only on the version in the proxy server's
banner, which is not updated by either of the patches the project has
released to address the issue. If one of those has been applied
properly and the service is restarted, consider this to be a false
positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2011_3.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Squid version 3.0.STABLE26 / 3.1.15 / 3.2.0.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Build a list of ports from the
list = get_kb_list("http_proxy/*/squid/version");
if (isnull(list)) exit(0, "The host does not appear to be running a Squid proxy server.");

vulnerable = FALSE;
foreach item (keys(list))
{
  port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];

  if (
    (version =~ '^3\\.0\\.(RC|PRE)[0-9]') ||
    (version =~ '^3\\.0\\.STABLE([0-9]|1[0-9]|2[0-5])([^0-9]|$)') ||
    (version =~ '^3\\.1\\.([0-9]|1[0-4])([^0-9]|$)') ||
    (version =~ '^3\\.2\\.0\\.([0-9]|10)([^0-9]|$)')
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      source = get_kb_item('http_proxy/'+port+'/squid/source');
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.0.STABLE26 / 3.1.15 / 3.2.0.11' + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
if (!vulnerable)
{
  exit(0, "No vulnerable Squid installs were detected on the remote host.");
}
