#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63318);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/15 14:21:39 $");

  script_cve_id("CVE-2012-5643");
  script_bugtraq_id(56957);
  script_osvdb_id(88492);
  
  script_name(english:"Squid 2.x / 3.x < 3.1.22 / 3.2.4 / 3.3.0.2 cachemgr.cgi DoS");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 2.x or 3.x prior to 3.1.22 / 3.2.4 / 3.3.0.2.  The included
'cachemgr.cgi' tool reportedly lacks input validation, which could be
abused by any client able to access that tool to perform a denial of
service attack on the service host. 
 
Note that Nessus did not actually test for this issue but has instead
relied on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2012_1.txt");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to Squid version 3.1.22 / 3.2.4 / 3.3.0.2 or later, or
apply the vendor-supplied patch. 

Alternatively, restrict access to this CGI or limit CGI memory
consumption via the host web server's configuration options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("squid_version.nasl");
  script_require_keys("www/squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Build a list of ports from the 
list = get_kb_list("http_proxy/*/squid/version");
if (isnull(list)) audit(AUDIT_NOT_INST, "Squid");

vulnerable = FALSE;
not_vuln_list = make_list();

foreach item (keys(list))
{
  port = ereg_replace(pattern:'^http_proxy/([0-9]+)/squid/version', replace:'\\1', string:item);
  version = list[item];
  # Affected:
  # Squid 2.x all releases
  # Squid 3.0 all releases
  # Squid 3.1 -> 3.1.21
  # Squid 3.2 -> 3.2.3
  # Squid 3.3.0.1
  if (
    (version =~ "^2\.") ||
    (version =~ "^3\.0\.") ||
    (version =~ "^3\.1\.([0-9]|1[0-9]|2[01])([^0-9]|$)") ||
    (version =~ "^3\.2\.[0-3]([^0-9]|$)") ||
    (version =~ "^3\.3\.0\.[01]([^0-9]|$)")
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      source = get_kb_item('http_proxy/'+port+'/squid/source');
      report = 
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.1.22 / 3.2.4 / 3.3.0.2' + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
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
