#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44400);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/26 16:30:03 $");

  script_cve_id("CVE-2009-2855");
  script_bugtraq_id(36091);
  script_osvdb_id(57193);
  script_xref(name:"Secunia", value:"36378");

  script_name(english:"Squid < 3.0.STABLE19 / 3.1.0.14 / 2.6.STABLE23 strListGetItem Function Remote DoS");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:"The remote proxy server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Squid proxy caching server
installed on the remote host is older than 3.0.STABLE19 / 3.1.0.14 /
2.6.STABLE23. A bug in the 'strListGetItem()' function in
'src/HttpHeaderTools.c' can result in an infinite loop when processing
a specially crafted auth header with certain comma delimiters.

A remote attacker may be able to leverage this issue to cause a denial
of service.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.squid-cache.org/show_bug.cgi?id=2541");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0f03356");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bf8993a");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d23f7691");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 3.0.STABLE19 / 3.1.0.14 / 2.6.STABLE23 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

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
    version =~ '^2\\.6\\.STABLE([0-9]|1[0-9]|2[0-2])([^0-9]|$)' ||
    version =~ '^3\\.0\\.STABLE([0-9}|1[0-8])([^0-9]|$)' ||
    version =~ '^3\\.1\\.0\\.([0-9]|1[0-9])([^0-9]|$)'
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 2.6.STABLE23/3.0.STABLE19/3.1.0.20\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
if (!vulnerable)
{
  exit(0, "No vulnerable Squid installs were detected on the remote host.");
}
