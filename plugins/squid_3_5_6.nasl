#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84674);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/14 13:43:57 $");

  script_osvdb_id(124237);

  script_name(english:"Squid < 3.5.6 Squid Cache Peer CONNECT Remote Access Bypass");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is potentially affected by an authentication
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is prior to 3.5.6. It is, therefore, potentially affected by an
authentication bypass vulnerability due to a flaw in file tunnel.cc,
which is triggered whenever cache peer CONNECT responses are blindly
forwarded in a hierarchy of two or more proxies, resulting in
unrestricted access to a back-end proxy through its gateway proxy. A
remote, unauthenticated attacker, using a specially crafted request,
can exploit this vulnerability to bypass authentication or gain access
to protected resources. This issue occurs in configurations with
cache_peer enabled, and exploitation would require that the two
proxies have differing levels of security.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number. The patch
released to address this issue does not update the version in the
banner. If the patch has been applied properly, and the service has
been restarted, consider this to be a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2015_2.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid versions 3.5.6 or later, or apply the vendor-supplied
patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/10");

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

  # Only supported versions or recently updated
  # versions are being flagged
  if (
    version =~ "^2\.[8-9]([^\.0-9]|$)" ||
    version =~ "^2\.[8-9]\.[0-9]+([^0-9]|$)" ||
    version =~ "^3\.[0-5]([^\.0-9]|$)" ||
    version =~ "^3\.[0-4]\.[0-9]+([^0-9]|$)" ||
    version =~ "^3\.5\.[0-5]([^0-9]|$)"
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      source = get_kb_item('http_proxy/'+port+'/squid/source');
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed versions    : 3.5.6' +
        '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
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
