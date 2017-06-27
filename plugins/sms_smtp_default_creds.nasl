#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24756);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_osvdb_id(53348);

  script_name(english:"Symantec Mail Security for SMTP Admin Center Default Credentials");
  script_summary(english:"Tries to authenticate to SMS for SMTP");

  script_set_attribute(attribute:"synopsis", value:
"An application hosted on the remote web server is protected with
default credentials." );
  script_set_attribute(attribute:"description", value:
"Symantec Mail Security for SMTP, which provides anti-spam and antivirus
protection for the IIS SMTP Service, is installed on the remote Windows
host. 

The installation of SMS for SMTP on the remote host uses a default
username / password combination to control access to its administrative
control center.  Knowing these, an attacker can gain control of the
affected application.");
  script_set_attribute(attribute:"solution", value:
"Use the control center to add another administrator or alter the
password for the 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 41443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:41443);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Make sure the affected script exists.
url = "/brightmail/login.do";
w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
res = w[2];

# If it does...
if (
  "Symantec Mail Security" >< res &&
  '<input type="text" name="username"' >< res
)
{
  install_url = build_url(qs:url, port:port);
  # Try to authenticate.
  user = "admin";
  pass = "symantec";
  postdata =
    "userLocale=&" +
    "username=" + user + "&" +
    "password=" + pass + "&" +
    "loginBtn=Login";

  w = http_send_recv3(method:"POST", item: url, port: port,
    content_type: "application/x-www-form-urlencoded",
    data: postdata, exit_on_fail:TRUE);
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # There's a problem if it looks like we were successful.
  if (
    "Location:" >< res &&
    egrep(pattern:"^Location: .+/brightmail/setup/SiteSetupEmbedded\$exec.flo", string:res)
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus was able to gain access using the following information :\n' +
        '\n' +
        '  URL      : ' + install_url +
        '  User     : ' + user + '\n' +
        '  Password : ' + pass + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else
    audit(AUDIT_WEB_APP_NOT_AFFECTED, "Symantec Mail Security for SMTP", install_url);
}
else audit(AUDIT_WEB_APP_NOT_INST, "Symantec Mail Security for SMTP", port);
