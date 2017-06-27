#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49693);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id("CVE-2010-3072");
  script_bugtraq_id(42982);
  script_osvdb_id(67824);
  script_xref(name:"Secunia", value:"41298");

  script_name(english:"Squid < 3.1.8 / 3.2.0.2 NULL Pointer Dereference Denial of Service");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid is 3.x earlier than than
3.1.8, or 3.2.x earlier than 3.2.0.2. Such versions are potentially
affected by a denial of service vulnerability caused by an internal
error in string handling. A remote attacker, exploiting this flaw,
could crash the affected service.

Note that Nessus has relied only on the version in the proxy server's
banner, which is not updated by either of the patches the project has
released to address the issue. If one of those has been applied
properly and the service restarted, consider this to be a false
positive.");

  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2010_3.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Squid version 3.1.8 / 3.2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
  source = get_kb_item('http_proxy/'+port+'/squid/source');

  if (
    (version =~ '^3\\.0\\.') ||
    (version =~ '^3\\.1\\.[0-7]($|[^0-9])') ||
    (version =~ '^3\\.2\\.0\\.[01]($|[^0-9])')
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.1.8/3.2.0.2' + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
if (!vulnerable)
{
  exit(0, "No vulnerable Squid installs were detected on the remote host.");
}
