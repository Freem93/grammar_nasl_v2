#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16190);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2014/05/26 16:30:03 $");

 script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0211", "CVE-2005-0241");
 script_bugtraq_id(12275, 12276, 12412, 12433, 12432, 12431, 13434, 13435);
 script_osvdb_id(12886, 12887, 13054, 13319, 13345, 13346, 13732);

 script_name(english:"Squid < 2.5.STABLE8 Multiple Vulnerabilities");
 script_summary(english:"Determines squid version");

 script_set_attribute(attribute:"synopsis", value:"The remote proxy server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Squid caching proxy is
affected by several security flaws :

  - There is a buffer overflow when handling the reply of a
    rogue gopher site. (CVE-2005-0094)

  - There is a denial of service vulnerability in the WCCP
    code of the remote proxy. (CVE-2005-0095)

  - There is a buffer overflow in the WCCP code that may
    allow an attacker to execute arbitrary code on the
    remote host. (CVE-2005-0211)

  - There is a flaw in the 'squid_ldap_auth' module that may
    allow an attacker to bypass authentication and to gain
    access to the remote proxy. (CVE-2005-0173)

  - There is a flaw in the way Squid parses HTTP reply
    headers. (CVE-2005-0241)

  - There is a weakness that may allow for cache poisoning
    via
    HTTP response splitting. (CVE-2005-0175)

  - There is a weakness that may allow for cache poisoning
    via
    crafted malformed headers. (CVE-2005-0174)

Note that this may be a false-positive given the way the Squid team
handles releases. Make sure that all the appropriate patches have been
applied.");
 script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Versions/v2/2.5/bugs/");
 script_set_attribute(attribute:"solution", value:"Upgrade to Squid 2.5.STABLE8 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/18");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 script_dependencie("squid_version.nasl");
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

  if (
    version =~ '^2\\.[0-4]\\.' ||
    version =~ '^2\\.5\\.STABLE[0-7]([^0-9]|$)'
  )
  {
    vulnerable = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + source +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 2.5.STABLE8' + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port:port);
  }
}
if (!vulnerable)
{
  exit(0, "No vulnerable Squid installs were detected on the remote host.");
}
