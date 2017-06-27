#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29216);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/05/26 16:30:02 $");

  script_cve_id("CVE-2007-6239", "CVE-2008-1612");
  script_bugtraq_id(26687, 28693);
  script_osvdb_id(39381, 44276);

  script_name(english:"Squid < 2.6.STABLE18 Cache Update Reply Unspecified DoS");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:"The remote proxy server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Squid proxy caching server
installed on the remote host is older than 2.6.STABLE18. Such versions
reportedly use incorrect bounds checking when processing some cache
update replies. A client trusted to use the service may be able to
leverage this issue to crash the application, thereby denying service
to legitimate users.

Note that an earlier version of the advisory said 2.6.STABLE17 fixed
the issue, but it turned out that the patch did not fully address the
issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2007_2.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484662/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to Squid version 2.6.STABLE18 or later or apply the
patch referenced in the project's advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy",3128, 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Build a list of ports from the KB
list = get_kb_list("http_proxy/*/squid/version");
if (isnull(list)) exit(0, "The host does not appear to be running Squid proxy server.");

vulnerable = FALSE;
foreach item (keys(list))
{
  port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];
  source = get_kb_item('http_proxy/'+port+'/squid/source');

  if (
    (version =~ '^[01]\\.') ||
    (version =~ '^2\\.[0-5]\\.') ||
    (version =~ '^2\\.6\\.STABLE([0-9]|1[0-7])([^0-9]|$)')
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 2.6.STABLE18' + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
if (!vulnerable)
{
  exit(0, "No vulnerable Squid installs were detected on the remote host.");
}
