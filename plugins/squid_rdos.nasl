#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15463);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/05/12 14:55:05 $");

 script_cve_id("CVE-2004-0918");
 script_bugtraq_id(11385);
 script_osvdb_id(10675);

 script_name(english:"Squid SNMP Module asn_parse_header() Function Remote DoS");
 script_summary(english:"Determines squid version");

 script_set_attribute(attribute:"synopsis", value:"The remote proxy server is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"The remote Squid caching proxy, according to its version number, may
be vulnerable to a remote denial of service attack.

This flaw is caused due to an input validation error in the SNMP
module, and exploitation requires that Squid not only was built to
support it but also configured to use it.

An attacker can exploit this flaw to crash the server with a specially
crafted UDP packet.

Note that Nessus reports this vulnerability using only the version
number in Squid's banner, so this might be a false positive.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02d8db5a");
 script_set_attribute(attribute:"solution", value:"Upgrade to squid 2.5.STABLE7 / squid 3.0.STABLE7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/05");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/02/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/12");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 script_dependencie("find_service1.nasl", "redhat-RHSA-2004-591.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/http_proxy",3128, 8080);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( get_kb_item("CVE-2004-0918") ) exit(0);

port = get_kb_item("Services/http_proxy");
if(!port)
{
 if(get_port_state(3128))
 {
  port = 3128;
 }
 else port = 8080;
}

if(get_port_state(port))
{
  res = http_get_cache(item:"/", port:port);
  if(egrep(pattern:"[sS]quid/2\.([0-4]\.|5\.STABLE[0-6]([^0-9]|$))", string:res) ||
     egrep(pattern:"[sS]quid/3\.0\.(0|STABLE[1-6]([^0-9]|$))", string:res))
      security_warning(port);
}
