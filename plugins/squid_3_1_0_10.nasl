#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82530);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/03 13:28:13 $");

  script_cve_id("CVE-2015-0881");
  script_bugtraq_id(72703);
  script_osvdb_id(118595);

  script_name(english:"Squid < 3.1.0.10 HTTP Header Injection Vulnerability");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by an HTTP header injection
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid is 0.x, 1.x, 2.x and 
3.x earlier than 3.1.0.10. Such versions are potentially affected by 
an HTTP Header Injection vulnerability. A remote attacker, exploiting 
this flaw could create a CRLF condition. (CVE-2015-0881) 
");

  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN64455813/index.html");
  # http://www.squid-cache.org/Versions/v3/3.1/changesets/SQUID_3_1_0_10.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3312aa23");
  script_set_attribute(attribute:"solution", value:"Upgrade to Squid version 3.1.0.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Squid";

# Build a list of ports from the
list = get_kb_list("http_proxy/*/squid/version");
if (isnull(list)) audit(AUDIT_NOT_DETECT, app_name);

vulnerable = FALSE;
foreach item (keys(list))
{
  port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];
  source = get_kb_item('http_proxy/'+port+'/squid/source');

   if (
    (version =~ '^0\\.') ||
    (version =~ '^1\\.') ||
    (version =~ '^2\\.') ||
    (version =~ '^3\\.0\\.') ||
    (version =~ '^3\\.1\\.0\\.([0-9])([^0-9]|$)')
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.1.0.10' + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
if (!vulnerable)
{
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port);
}
