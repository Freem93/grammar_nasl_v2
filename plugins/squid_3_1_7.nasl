#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48433);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id("CVE-2010-2951");
  script_bugtraq_id(42645);
  script_osvdb_id(67618);

  script_name(english:"Squid 3.1.6 DNS Reply Denial of Service");
  script_summary(english:"Checks version of Squid in its banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Squid proxy caching server
installed on the remote host is 3.1.6. This version is affected by a
denial of service vulnerability that is caused by an assertion failure
when contacting IPv4-only DNS resolvers.

Note that Nessus has relied only on the version in the proxy server's
banner, which is not updated by either of the patches the project has
released to address this issue. If one of those has been applied
properly and the service restarted, consider this to be a false
positive.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.squid-cache.org/show_bug.cgi?id=3021");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/mail-archive/squid-users/201008/0480.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Squid version 3.1.7 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


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

  if (version =~ '3\\.1\\.6([^0-9]|$)')
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.1.7\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
if (!vulnerable) exit(0, "No vulnerable versions of Squid were detected on the remote host.");
