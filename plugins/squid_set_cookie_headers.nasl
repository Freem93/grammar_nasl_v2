#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19237);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/05/26 16:30:03 $");

  script_cve_id("CVE-2005-0626");
  script_bugtraq_id(12716);
  script_osvdb_id(14354);

  script_name(english:"Squid Set-Cookie Header Cross-session Information Disclosure");
  script_summary(english:"Checks for Set-Cookie headers information disclosure vulnerability in Squid");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by an information disclosure
issue.");
  script_set_attribute(attribute:"description", value:
"The remote Squid caching proxy, according to its banner, is prone to
an information disclosure vulnerability. Due to a race condition,
Set-Cookie headers may leak to other users if the requested server
employs the deprecated Netscape Set-Cookie specifications with regards
to how cacheable content is handled.");
  # http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE9-setcookie
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e1802e8");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor URL above or upgrade to
version 2.5 STABLE10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
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
    version =~ '^2\\.5\\.STABLE[0-9]([^0-9]|$)'
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 2.5.STABLE10' + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
if (!vulnerable)
{
  exit(0, "No vulnerable Squid installs were detected on the remote host.");
}
