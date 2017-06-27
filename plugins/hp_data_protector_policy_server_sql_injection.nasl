#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58527);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2011-3156");
  script_bugtraq_id(50181);
  script_osvdb_id(76701);

  script_name(english:"HP Data Protector LogClientInstallation Method Userid Field SQL Execution");
  script_summary(english:"Checks whether inserting an illegal character in an XML field causes a database error");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Data Protector install is vulnerable to a SQL injection
attack.");
  script_set_attribute(attribute:"description", value:
"The HP Data Protector DPNECentral web service listening on this port
contains a SQL injection vulnerability because it fails to properly
sanitize user-supplied input to the userid field of its
LogClientInstallation method before using it in a database query.
This may allow an attacker to read and write sensitive data, or
possibly run arbitrary code on the server.

This vulnerability affects HP Data Protector Notebook Extension and HP
Data Protector for Personal Computers.

Note that this install is likely affected by several other SQL
injection vulnerabilities, though Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-326/");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03058866-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60f69832");
  script_set_attribute(attribute:"solution", value:"Install the DPPCWIN_00001 patch from the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector_notebook_extension");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_data_protector_policy_server_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/dpnepolicyservice");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:"dpnepolicyservice", port:port, exit_on_fail:TRUE);
uri = install["dir"] + "/DPNECentral.asmx";

# The vulnerability is in the 'userid' field
postdata = '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <LogClientInstallation xmlns="http://hp.com/">
      <machine>string</machine>
      <userid>string\'</userid>
      <username>string</username>
      <domain>string</domain>
      <finished>0</finished>
      <errorCode>0</errorCode>
      <errorMessage>string</errorMessage>
    </LogClientInstallation>
  </soap:Body>
</soap:Envelope>
';

r = http_send_recv3(method: "POST", port: port, item:uri, data: postdata, add_headers: make_array("Content-Type", "text/xml; charset=utf-8", "SOAPAction", '"http://hp.com/LogClientInstallation"'));

if("500" >< r[0] && "Incorrect syntax near 'string'" >< r[2])
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue exists using the following request :' +
      '\n' +
      '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
      '\n' + http_last_sent_request() +
      '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The HP Data Protector install at "+build_url(port:port, qs:uri)+" is not affected.");
