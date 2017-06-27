#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40420);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2621", "CVE-2009-2622");
  script_bugtraq_id(35812);
  script_osvdb_id(56680, 56681);

  script_name(english:"Squid 3.0.STABLE16 / 3.10.11");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:"The remote proxy server is prone to denial of service attacks.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Squid proxy caching server
installed on the remote host is older than 3.0.STABLE17 or 3.1.0.12.
Such versions reportedly use incorrect bounds checking when processing
some requests or responses.

Squid-2.x releases are not vulnerable.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2009_2.txt");
  script_set_attribute(attribute:"see_also", value: "http://www.securityfocus.com/advisories/17446");
  script_set_attribute(attribute:"see_also", value: "http://www.securityfocus.com/advisories/17448");
  script_set_attribute(attribute:"see_also", value: "http://www.securityfocus.com/advisories/17483");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to Squid version 3.0.STABLE17 or 3.1.0.12 or later or
apply the patch referenced in the project's advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy",3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Buid a list of ports from the KB
list = get_kb_list("http_proxy/*/squid/version");
if (isnull(list)) exit(0, "The host does not appear to be running a Squid proxy server.");

vulnerable = FALSE;
foreach item (keys(list))
{
  port = ereg_replace(pattern:'http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];
  source = get_kb_item('http_proxy/'+port+'/squid/source');

  if (
    (version =~ '^3\\.0\\.STABLE([0-9]|1[0-6])($|[^0-9])') ||
    (version =~ '^3\\.1\\.0\\.([0-9]|1[01])($|[^0-9])')
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.0.STABLE17/3.1.0.12\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
if (!vulnerable)
{
  exit(0, "No vulnerable Squid installs were detected on the remote host.");
}
