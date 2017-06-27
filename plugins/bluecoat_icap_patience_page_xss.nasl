#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69442);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2008-4485");
  script_bugtraq_id(31543);
  script_osvdb_id(48753);
  script_xref(name:"IAVT", value:"2008-T-0060");

  script_name(english:"Blue Coat ICAP Patience Page XSS");
  script_summary(english:"Detects an XSS issue in ProxySG");

  script_set_attribute(attribute:"synopsis", value:
"The remote HTTP proxy server is vulnerable to a XSS issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Blue Coat ProxySG that suffers
from a XSS issue.

An attacker can exploit this issue by sending a malicious link that will
redirect the user to the ICAP 'Patience' page which will echo the link
back, unfiltered.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=122210321731789&w=2");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("proxy_use.nasl");
  script_require_keys("Proxy/usage");
  script_require_ports("Services/http_proxy", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item_or_exit("Services/http_proxy");
get_kb_item_or_exit("Proxy/usage");

res = http_send_recv3(item:"http://rfi.nessus.org/bluecoat.exe?<foo>", port:port, method:"GET");
if ( isnull(res) ) exit(0);

if ( "<title>Please be patient</title>" >< res[2] &&
     '<td valign="top" width="30%">URL:</td>' >< res[2] &&
     '<td valign="top"><foo></td>' >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  security_warning(port);
}
else exit(0, "Not vulnerable.");
