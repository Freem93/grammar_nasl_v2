#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12124);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2014/05/26 16:30:03 $");

  script_cve_id("CVE-2004-0189");
  script_bugtraq_id(9778);
  script_osvdb_id(5916);

  script_name(english:"Squid %xx URL Encoding ACL Bypass");
  script_summary(english:"Determines squid version");

  script_set_attribute(attribute:'synopsis', value:"The remote service is vulnerable to an authentication bypass.");
  script_set_attribute(attribute:'description', value:
"The remote squid caching proxy, according to its version number, is
vulnerable to a flaw that could allow an attacker to gain access to
unauthorized resources.

The flaw itself consists of sending a malformed username containing
the %00 (null) character, which could allow an attacker to access
otherwise restricted resources.");
  script_set_attribute(attribute:'see_also', value:"http://www.squid-cache.org/Advisories/SQUID-2004_1.txt");
  script_set_attribute(attribute:'solution', value:"Upgrade to squid 2.5.STABLE6 or newer");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");

  script_dependencie("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy",3128, 8080);

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
    version =~ '^2\\.[0-4]\\.' ||
    version =~ '^2\\.5\\.STABLE[0-4]([^0-9]|$)'
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 2.5.STABLE5' + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port:port);
  }
}
if (!vulnerable)
{
  exit(0, "No vulnerable Squid installs were detected on the remote host.");
}
