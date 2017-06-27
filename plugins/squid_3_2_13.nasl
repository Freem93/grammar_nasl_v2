#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69042);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2013-4123");
  script_bugtraq_id(61159, 61182);
  script_osvdb_id(95257);
  script_xref(name:"EDB-ID", value:"26886");

  script_name(english:"Squid 3.2.x < 3.2.13 / 3.3.x < 3.3.8 Port Handling DoS");
  script_summary(english:"Checks version of Squid");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Squid running on the remote
host is 3.2.x prior to 3.2.13 or 3.3.x prior to 3.3.8.  It is,
therefore, affected by a denial of service vulnerability.  The
vulnerability exists when handling a port number in the host header of a
specially crafted HTTP Request. 

Note that Nessus has relied only on the version in the proxy server's
banner, which is not updated by the patch that the project has released
to address this issue.  If this patch has been applied properly and the
service has been restarted, consider this to be a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2013_3.txt");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Jul/98");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to Squid version 3.2.13 / 3.3.8 or later, or apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

  # Squid 3.2.x < 3.2.13
  # Squid 3.3.x < 3.3.8
  if (
    version =~ "^3\.2\.([0-9]|1[0-2])([^0-9]|$)" ||
    version =~ "^3\.3\.[0-7]([^0-9]|$)"
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      source = get_kb_item('http_proxy/'+port+'/squid/source');
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 3.2.13 / 3.3.8' + '\n';
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
