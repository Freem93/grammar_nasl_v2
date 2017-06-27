#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77985);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/30 17:51:57 $");

  script_cve_id("CVE-2014-3609");
  script_bugtraq_id(69453);
  script_osvdb_id(110525);

  script_name(english:"Squid 3.x < 3.3.13 / 3.4.7 Request Processing DoS");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 3.x prior to 3.3.13 or 3.4.7. It is, therefore, affected by a
denial of service vulnerability.

The flaw exists due to user-supplied input not being properly
validated in request parsing. This allows a remote attacker to
specially craft a request with Range headers with unidentifiable
byte-range values to crash the application.

Note that Nessus has relied only on the version in the proxy server's
banner. The patch released to address the issue does not update the
version in the banner. If the patch has been applied properly, and the
service has been restarted, consider this to be a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2014_2.txt");
  # http://www.squid-cache.org/Versions/v3/3.4/changesets/SQUID_3_4_7.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9a745a4");
  # http://www.squid-cache.org/Versions/v3/3.3/changesets/SQUID_3_3_13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2b5e3b7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 3.3.13 / 3.4.7 or later, or apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Build a list of ports from the
list = get_kb_list("http_proxy/*/squid/version");
if (isnull(list)) audit(AUDIT_NOT_INST, "Squid");

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vulnerable = FALSE;
not_vuln_list = make_list();

foreach item (keys(list))
{
  port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];

  # Affected:
  # Squid 3.x < 3.3.13
  # Squid 3.4.x < 3.4.7
  if (
    version =~ "^3\.[0-2]([^0-9]|$)" ||
    version =~ "^3\.3\.([0-9]|1[0-2])([^0-9]|$)" ||
    version =~ "^3\.4\.[0-6]([^0-9]|$)"
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      source = get_kb_item('http_proxy/'+port+'/squid/source');
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.3.13 / 3.4.7' + 
        '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
  else not_vuln_list = make_list(not_vuln_list, version + " on port " + port);
}

if (vulnerable) exit(0);
else
{
  installs = max_index(not_vuln_list);
  if (installs == 0) audit(AUDIT_NOT_INST, "Squid");
  else if (installs == 1)
    audit(AUDIT_INST_VER_NOT_VULN, "Squid", not_vuln_list[0]);
  else
    exit(0, "The Squid installs ("+ join(not_vuln_list, sep:", ") + ") are not affected.");
}
