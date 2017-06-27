#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72258);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_cve_id("CVE-2013-3319");
  script_bugtraq_id(61402);
  script_osvdb_id(95616);

  script_name(english:"SAP Host Agent SOAP Web Service Information Disclosure (SAP Note 1816536)");
  script_summary(english:"Attempts to make a SOAP request.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a SOAP service that discloses sensitive
information.");
  script_set_attribute(attribute:"description", value:
"The version of SAP Host Agent discloses sensitive system information,
such as operating system version, databases version, CPU make and model,
and information on network interfaces.  A remote, unauthenticated
attacker could use this to specialize attacks.");
  script_set_attribute(attribute:"see_also", value:"https://service.sap.com/sap/support/notes/1816536");
  script_set_attribute(attribute:"see_also", value:"http://labs.integrity.pt/advisories/cve-2013-3319/");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("sap_host_control_detect.nasl");
  script_require_keys("www/sap_host_control");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "SAP Host Agent";

# Note that we're looking for SAP Host Agent, but we're using the SAP
# Host Control information. That's because the two are related in some
# way that I've failed to understand, possibly one spawns or hosts the
# other and that's why they're both referenced as being on the same
# port.
port = get_http_port(default:1128, embedded:TRUE);
install = get_install_from_kb(appname:"sap_host_control", port:port, exit_on_fail:TRUE);
dir = install["dir"];
url = build_url(port:port, qs:dir + "/");

# Build the SOAP request.
xml = '<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <SOAP-ENV:Header>
    <sapsess:Session xlmns:sapsess="http://www.sap.com/webas/630/soap/features/session/">
      <enableSession>true</enableSession>
    </sapsess:Session>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <ns1:GetComputerSystem xmlns:ns1="urn:SAPHostControl">
      <aArguments>
        <item>
          <mKey>provider</mKey>
          <mValue>saposcol</mValue>
        </item>
      </aArguments>
    </ns1:GetComputerSystem>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>';

# Attempt to send the SOAP request.
res = http_send_recv3(
  port         : port,
  method       : "POST",
  item         : dir + "/",
  data         : xml,
  exit_on_fail : TRUE
);

if ("<SAPHostControl:GetComputerSystemResponse>" >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to execute a GetComputerSystem request through' +
    '\n' + 'the SAP Host Agent. The request sent was :' +
    '\n' +
    '\n  ' + join(split(xml, sep:'\n', keep:FALSE), sep:'\n  ') +
    '\n';

  if (report_verbosity > 1)
  {
    report +=
      '\n' + 'The response to the above request was :' +
      '\n' +
      '\n  ' + join(split(res[2], sep:'\n', keep:FALSE), sep:'\n  ') +
      '\n';
  }
}

security_warning(port:port, extra:report);
