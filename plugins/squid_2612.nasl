#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24873);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/05/26 16:30:02 $");

  script_cve_id("CVE-2007-1560");
  script_bugtraq_id(23085);
  script_osvdb_id(34367);

  script_name(english:"Squid < 2.6.STABLE12 src/client_side.c clientProcessRequest() function TRACE Request DoS");
  script_summary(english:"Determines squid version");

  script_set_attribute(attribute:"synopsis", value:"The remote proxy server is vulnerable to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in TRACE request processing has been reported in
Squid, which can be exploited by malicious people to cause a denial of
service.");
  script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Advisories/SQUID-2007_1.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to squid 2.6.STABLE12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");

  script_dependencies("proxy_use.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/http_proxy",3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ports = make_service_list(3128, 8080, "Services/http_proxy");

foreach port (ports)
 if(get_port_state(port))
 {
  res = http_get_cache(item:"/", port:port);
  if(res && egrep(pattern:"[Ss]quid/2\.([0-5]\.|6\.STABLE([0-9][^0-9]|1[01][^0-9]))", string:res))
   security_warning(port);
 }
