#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79742);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/05 18:12:30 $");

  script_cve_id("CVE-2014-6270", "CVE-2014-7141", "CVE-2014-7142");
  script_bugtraq_id(69686, 69688, 70022);
  script_osvdb_id(111286, 111420, 112409);

  script_name(english:"Squid 3.x < 3.4.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Squid.");

  script_set_attribute(attribute:"synopsis", value:"The remote proxy server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 3.x prior to 3.4.8. Therefore, it may be affected by the
following vulnerabilities :

  - A off-by-one overflow flaw exists within the SNMP
    processing component. By using a specially crafted
    UDP SNMP request, a remote attacker could exploit this
    to cause a denial of service or possibly execute
    arbitrary code. (CVE-2014-6270)

  - There exists an array indexing flaw in the node pinger
    that is triggered when parsing ICMP and ICMPv6 replies,
    which may allow a remote attacker to crash the pinger or
    obtain sensitive information. (CVE-2014-7141)

  - The node pinger has a flaw in function 'Icmp4::Recv' in
    file 'icmp/Icmp4.cc.' that is triggered when parsing
    ICMP or ICMPv6 responses. A remote attacker could
    exploit this to crash the pinger or obtain sensitive
    information. (CVE-2014-7142)

Note that Nessus has relied only on the version in the proxy server's
banner. The patch released to address the issue does not update the
version in the banner. If the patch has been applied properly, and the
service has been restarted, consider this to be a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2014_3.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2014_4.txt");
  # http://www.squid-cache.org/Versions/v3/3.4/changesets/SQUID_3_4_8.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9716bf4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 3.4.8 or later, or apply the vendor-supplied
patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/05");

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
  # Squid 2.x
  # Squid 3.x < 3.4.8
  if (
    version =~ "^2\." ||
    version =~ "^3\.[0-3]([^0-9]|$)" ||
    version =~ "^3\.4\.[0-7]([^0-9]|$)"
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      source = get_kb_item('http_proxy/'+port+'/squid/source');
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.4.8' +
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
