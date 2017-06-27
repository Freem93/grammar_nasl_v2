#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44384);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id("CVE-2010-0308");
  script_bugtraq_id(37522);
  script_osvdb_id(62044);
  script_xref(name:"Secunia", value:"38451");
  script_xref(name:"Secunia", value:"38455");

  script_name(english:"Squid < 3.0.STABLE23 / 3.1.0.16");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:"The remote proxy server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Squid proxy caching server
installed on the remote host is 2.x or older than 3.0.STABLE23 /
3.1.0.16. Such versions reportedly fail to correctly validate DNS
packets, which can be abused by a remote attack to cause a short-term
denial of service.

Note that Nessus has relied only on the version in the proxy server's
banner, which is not updated by either of the patches the project has
released to address this issue. If one of those has been applied
properly and the service restarted, consider this to be a false
positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2010_1.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9140f7e2");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e06892d");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Versions/v2/HEAD/changesets/12597.patch");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to Squid version 3.0.STABLE23 / 3.1.0.16 or later or
apply the appropriate patch referenced in the project's advisory
above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
if (isnull(list)) exit(0, "The host does not appear to be running a Squid proxy server.");

vulnerable = FALSE;
foreach item (keys(list))
{
  port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];
  source = get_kb_item('http_proxy/'+port+'/squid/source');

  if (
    (version =~ '^2\\.') ||
    (version =~ '^3\\.0\\.STABLE([0-9]|1[0-9]|2[0-2])($|[^0-9])') ||
    (version =~ '^3\\.1\\.0\\.([0-9]|1[0-5])([^0-9]|$)')
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.0.STABLE23/3.1.0.16\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
if (!vulnerable)
{
  exit(0, "No vulnerable Squid installs were detected on the remote host.");
}
