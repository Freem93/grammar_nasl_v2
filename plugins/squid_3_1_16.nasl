#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57287);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/26 16:30:02 $");

  script_cve_id("CVE-2011-4096");
  script_bugtraq_id(50449);
  script_osvdb_id(76742);

  script_name(english:"Squid 3.1.x < 3.1.16 / 3.2.x < 3.2.0.13 DNS Replies CName Record Parsing Remote DoS");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid is 3.1.x earlier than
than 3.1.16 or 3.2.x earlier than 3.2.0.13. Such versions are affected
by a denial of service vulnerability.

The application does not properly free memory when handling DNS
replies containing a CNAME record that references another CNAME record
that contains an empty A record.

Note that Nessus has relied only on the version in the proxy server's
banner, which is not updated by the patch that the project has
released to address the issue. If the patch has been applied properly
and the service restarted, consider this to be a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Versions/v3/3.1/changesets/SQUID_3_1_16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?437bac7c");
  script_set_attribute(attribute:"see_also", value:"http://bugs.squid-cache.org/show_bug.cgi?id=3237");
  script_set_attribute(attribute:"solution", value:"Upgrade to Squid version 3.1.16 / 3.2.0.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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

  # 3.1.0 - 3.1.15
  # 3.2.0.0 - 3.2.0.12
  if (
    (version =~ '^3\\.1\\.([0-9]|1[0-5])($|[^0-9])') ||
    (version =~ '^3\\.2\\.0\\.([0-9]|1[0-2])($|[^0-9])')
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.1.16/3.2.0.13' + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
if (!vulnerable) exit(0, "No vulnerable Squid installs were detected on the remote host.");
