#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19598);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_name(english:"Brightmail Control Center Default Password (symantec) for 'admin' Account");
  script_summary(english:"Checks for default account / password in Brightmail Control Center");

  script_set_attribute(attribute:"synopsis", value:"The remote server uses known authentication credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Symantec's Brightmail Control Center, a
web-based administration tool for Brightmail AntiSpam. 

The installation of Brightmail Control Center on the remote host still
has an account 'admin' with the default password 'symantec'.  An
attacker can exploit this issue to gain access of the Control Center and
any scanners it controls.");
  script_set_attribute(attribute:"solution", value:
"Log in to the Brightmail Control Center and change the password for the
'admin' user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 41080, 41443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


port = get_http_port(default:41080);

# Check whether the login script exists.
r = http_send_recv3(method:"GET", item:"/brightmail/viewLogin.do", port:port, exit_on_fail:TRUE);

# If it does...
if ('<form name="logonForm" action="login.do"' >< r[2])
{
  # Try to log in.
  user = "admin";
  pass = "symantec";
  postdata = string(
    "path=&",
    "compositeId=&",
    "username=", user, "&",
    "password=", pass
  );
  r = http_send_recv3(method: "POST", item: "/brightmail/login.do", version: 11, port: port,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
    data: postdata, exit_on_fail:TRUE);

  # There's a problem if we get redirected to a start page.
  if (egrep(string:r[1], pattern:"^Location: .+/findStartPage.do"))
  {
    security_hole(port);
    exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN, "Brightmail Control Center", port);
