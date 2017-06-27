#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27526);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_name(english:"CA Host-Based Intrusion Prevention System Server Default Credentials");
  script_summary(english:"Tries to login to CA HIPS with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web service is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Computer Associates' Host-Based Intrusion
Prevention System (CA HIPS) Server, an intrusion prevention system for
Windows. 

The remote installation of CA HIPS Server is configured to use default
credentials to control access.  Knowing these, an attacker can gain
control of the affected application.");
  script_set_attribute(attribute:"solution", value:
"Change the password for the 'admin' account by logging into the CA HIPS
server, navigating to 'Global Settings / Administrators', and editing
the 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 1443);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:1443);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

init_cookiejar();

user = "admin";
pass = "admin";

# Check whether the login script exists.
url = "/hss/hss";
r = http_send_recv3(method: 'GET', item: "/hss/hss?pg=login.ftl", port:port, exit_on_fail:TRUE);

install_url = build_url(qs:url, port:port);

# If it does...
if ('<form  id="_AuthLogin"' >< r[2])
{
  # Extract the session identifier.
  sid = NULL;
  pat = 'action="/hss/hss\\?s=([^&]+)&cm=AuthLogin"';
  matches = egrep(pattern:pat, string: r[2]);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      value = eregmatch(pattern:pat, string:match);
      if (!isnull(value))
      {
        sid = value[1];
        break;
      }
    }
  }
  if (isnull(sid))
  {
    exit(0,"Can't extract the session identifier!");
  }

  # Try to log in.
  postdata = 
    "redir_e=login.ftl&" +
    "redir=main.ftl&" +
    "sessionOnly=false&" +
    "loginName=" + user + "&" +
    "password=" + pass + "&" +
    "submit=Login";
  r = http_send_recv3(port:port, method: 'POST', version: 11,
 item: url + "?s=" + sid + "&cm=AuthLogin", data: postdata,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
 exit_on_fail: TRUE);

  # There's a problem if the admin cookie is set.
  if ("Set-Cookie: HIPS_S_" >< r[1] && r[1] =~ "Set-Cookie: HIPS_S_[0-9]+=admin")
  {
    if (report_verbosity > 0)
    {
      report =
        'Nessus was able to gain access using the following credentials :\n' +
        '\n' +
        '  URL      : ' + install_url + '\n' +
        '  User     : ' + user + '\n' +
        '  Password : ' + pass + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "CA Host-Based Intrusion Prevention System", install_url);
