#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52756);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/08 15:38:46 $");

  script_cve_id("CVE-2010-4437");
  script_bugtraq_id(45852);
  script_osvdb_id(70571);

  script_name(english:"Oracle WebLogic Server Servlet Container Session Fixation");
  script_summary(english:"Attempts to simulate a session fixation attack");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web server running on the remote host has a session fixation
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Oracle WebLogic Server running on the remote host has
a session fixation vulnerability. 

A remote attacker could exploit this by tricking a user into making a
specially crafted POST request.  This would allow the attacker to
hijack the user's session."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e08549d8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the relevant patch referenced by the Oracle advisory."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2011/01/18");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("weblogic_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 7001);
  script_require_keys("www/weblogic");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");

appname = "WebLogic";
get_kb_item_or_exit("www/weblogic");
port = get_http_port(default:7001);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");
url = '/console/login/LoginForm.jsp';
full_url = build_url(qs:url, port:port);
attempt = 1;  # used by error reporting in get_admin_cookie()

##
# Tries to get the ADMINCONSOLESESSION from the given web server response.
#
# This function will exit() if it's unable to extract the session ID
#
# @anonparam  res  web server response to extract the session ID from. expects the format returned by http_send_recv3()
#
# @return the ADMINCONSOLESESSION ID
##
function get_admin_sessionid()
{
  local_var res, headers, cookie, sessionid;
  res = _FCT_ANON_ARGS[0];

  # Then try to extract the session ID from the response
  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(headers)) audit(AUDIT_RESP_BAD, port);

  cookie = headers['set-cookie'];
  if (isnull(cookie)) audit(AUDIT_RESP_BAD, port);
  sessionid = get_any_http_cookie(name:'ADMINCONSOLESESSION');
  if (strlen(sessionid) == 0) audit(AUDIT_RESP_BAD, port);

  return sessionid;
}


# First, try to get a valid session ID
clear_cookiejar();
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

# Make sure it actually looks like WebLogic unless we're paranoid
if (
  report_paranoia < 2 &&
  '<TITLE>BEA WebLogic Server Administration Console</TITLE>' >!< res[2] &&
  '<title>Oracle WebLogic Server Administration Console</title>' >!< res[2] &&
  '<TITLE>WebLogic Server' >!< res[2]
) audit(AUDIT_INST_VER_NOT_VULN, appname);

# Then try to extract the session ID from the response
sessionid1 = get_admin_sessionid(res);

# Lastly try to fingerprint the attack
clear_cookiejar();
payload = 'ADMINCONSOLESESSION='+sessionid1;
res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:payload,
  exit_on_fail:TRUE
);
sessionid2 = get_admin_sessionid(res);

if (sessionid1 == sessionid2)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus verified this by specifying a session ID in the request :\n\n'+
      crap(data:"-", length:30)+ ' snip ' +crap(data:"-", length:30)+ '\n' +
      http_last_sent_request() + '\n' +
      crap(data:"-", length:30)+ ' snip ' +crap(data:"-", length:30)+ '\n';

      report +=
        '\nAnd being offered the same session ID in the response :\n\n'+
        crap(data:"-", length:30)+ ' snip ' +crap(data:"-", length:30)+ '\n' +
        res[0] + res[1] +
        crap(data:"-", length:30)+ ' snip ' +crap(data:"-", length:30)+ '\n';

    security_warning(port:port, extra:report);
    exit(0);
  }
  else
  {
    security_warning(port);
    exit(0);
  }
}
audit(AUDIT_INST_VER_NOT_VULN, appname);
