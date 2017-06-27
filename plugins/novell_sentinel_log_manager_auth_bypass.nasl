#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62968);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/27 15:14:57 $");

  script_cve_id("CVE-2012-6534");
  script_bugtraq_id(55767);
  script_osvdb_id(85955);
  script_xref(name:"EDB-ID", value:"21744");

  script_name(english:"Novell Sentinel Log Manager Authentication Bypass");
  script_summary(english:"Tries to get SLM version without authentication");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote host has an authentication
bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Novell Sentinel Log Manager hosted on the remote web
server has an authentication bypass vulnerability.  It is possible to
execute GWT-RPC methods without authentication.  A remote,
unauthenticated attacker could exploit this to perform actions that
should require administrative privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Oct/25");
  # https://www.netiq.com/documentation/novelllogmanager12/log_manager_readme/data/log_manager_readme.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b316636b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell Sentinel Log Manager 1.2.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:sentinel_log_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_sentinel_log_manager_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8443);
  script_require_keys("www/novell_slm");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("path.inc");
include("json.inc");

GWT_RPC_SUCCESS = '//OK';
GWT_RPC_FAILURE = '//EX';

port = get_http_port(default:8443);
transport = get_kb_item_or_exit('Transports/TCP/' + port);
install = get_install_from_kb(appname:'novell_slm', port:port, exit_on_fail:TRUE);
base_url = build_url(qs:install['dir'], port:port);

if (transport > ENCAPS_IP)
  proto = 'https';
else
  proto = 'http';

gwtrpc_req =
  '5|' +
  '0|' +
  '4|' +
  # e.g., https://10.10.10.10:8443//novelllogmanager/com.novell.siem.logmanager.LogManager/|
  proto + '://' + get_host_ip() + ':' + port + install['dir'] + '/com.novell.siem.logmanager.LogManager/|' +
  '9C197F61D45E23F76A92BBBC3079B09F|' +
  'com.novell.sentinel.scout.client.about.AboutLogManagerService|' +
  'getLogManagerInfo|' +
  '1|' +
  '2|' +
  '3|' +
  '4|' +
  '0|';
res = http_send_recv3(
  method:'POST',
  item:install['dir'] + '/aboutlogmanager.rpc',
  port:port,
  content_type:'text/x-gwt-rpc',
  data:gwtrpc_req,
  exit_on_fail:TRUE
);

# Non-vulnerable systems respond with a HTTP 403 (Forbidden) since the
# the request was made without being authenticated
if (res[0] =~ "^HTTP/1\.[01] 403")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Novell SLM', base_url);

# The response doesn't begin with a GWT-RPC response status
status = substr(res[2], 0, 3);
if (strlen(status) != 4)
  audit(AUDIT_RESP_NOT, port, 'GWT-RPC request with a response status');

if ('The call failed on the server; see server log for details' >< res[2])
{
  # This error message means the GWT-RPC request did not succeed, likely because
  # the strongname (MD5 hash provided in the request) was not recognized.  Even
  # so, this still means the software is vulnerable because a patched system
  # would respond with an HTTP 403 instead of this error message
  invalid_strongname = TRUE;
}
else
{
  invalid_strongname = FALSE;
  gwtrpc_json = substr(res[2], 4);
  json_data = json_read(gwtrpc_json);

  # The response doesn't contain JSON, or doesn't contain JSON we can parse
  if (isnull(json_data[1]))
    audit(AUDIT_FN_FAIL, 'json_read', 'error: ' + json_data[0]);
  else
    gwtrpc_res = json_data[0];
}

if (status == GWT_RPC_SUCCESS)
{
  version = gwtrpc_res[4][3];
  report =
    '\nNessus determined the version of Novell Sentinel Log Manager by' +
    '\nexecuting the following GWT-RPC method without authentication :\n\n' +
    crap(data:"-" , length:30) +  " request below " + crap(data:"-", length:30) +
    '\n' + http_last_sent_request() +
    '\n' + crap(data:"-" , length:30) +  " request above " + crap(data:"-", length:30) + '\n' +
    '\nThe server reported the following version is installed :\n\n' +
    version + '\n';
}
else if (status == GWT_RPC_FAILURE || invalid_strongname)
{
  report =
    '\nNessus executed the following GWT-RPC method without authentication :\n\n' +
    crap(data:"-" , length:30) +  " request below " + crap(data:"-", length:30) +
    '\n' + http_last_sent_request() +
    '\n' + crap(data:"-" , length:30) +  " request above " + crap(data:"-", length:30) + '\n' +
    '\nThe software was successfully identified as vulnerable, even though the' +
    '\nmethod Nessus attempted to run failed (refer to the following error message).\n\n' +
    crap(data:"-" , length:30) +  " error below " + crap(data:"-", length:30) +
    '\n' + res[2] +
    '\n' + crap(data:"-" , length:30) +  " error above " + crap(data:"-", length:30) + '\n';
}
else
{
  audit(AUDIT_RESP_BAD, port, 'GWT-RPC request');
}

if (report_verbosity > 0)
  security_hole(port:port, extra:report);
else
  security_hole(port);

