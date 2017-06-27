#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65822);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/05 23:45:30 $");

  script_name(english:"Git Protocol Detection");
  script_summary(english:"Detects the git protocol");

  script_set_attribute(
    attribute:"synopsis",
    value:"A distributed version control server is running on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:"A Git daemon using the Git protocol is running on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://git-scm.com/book/ch4-1.html");
  # https://github.com/git/git/blob/master/Documentation/technical/pack-protocol.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8643f5c");
  script_set_attribute(
    attribute:"solution",
    value:
"Authentication is not required to use the Git protocol.  Ensure push
access is not enabled and only authorized hosts can access the service."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git:git");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 9418);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests)
{
  port = get_unknown_svc(9418);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (!silent_service(port)) audit(AUDIT_FN_FAIL, 'silent_service', strcat('false for port ', port));
}
else port = 9418;
if (known_service(port:port)) exit(0, 'The service on port ' + port + ' has already been identified.');
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

#   git-proto-request = request-command SP pathname NUL [ host-parameter NUL ]
#   request-command   = "git-upload-pack" / "git-receive-pack" /
#                       "git-upload-archive"   ; case sensitive
#   pathname          = *( %x01-ff ) ; exclude NUL
#   host-parameter    = "host=" hostname [ ":" port ]
# Example:
# 001fgit-receive-pack /foobarbaz\0
pathname = '/' + SCRIPT_NAME + '-' + unixtime();
req = 'git-receive-pack ' + pathname;
if (strlen(req) + 4 > 0xffff)
  exit(1, 'The plugin tried to make a request bigger than 0xffff bytes.');
else
{
  len = hexstr(mkword(strlen(req) + 4)); # the length field (2 bytes, in a hex string) is included
  req = len + req + '\0';
}

soc = open_sock_tcp(port);
if (!soc)
  audit(AUDIT_SOCK_FAIL, port);

send(socket:soc, data:req);
len = recv(socket:soc, length:4);
if (len !~ '^[A-Fa-f0-9]{4}$')
{
  close(soc);
  audit(AUDIT_RESP_BAD, port, 'git-receive-pack');
}

len = getword(blob:hex2raw(s:len)) - 4; # the length field (2 bytes, in a hex string) is included
res = recv(socket:soc, length:len);
close(soc);

# error-line     =  PKT-LINE("ERR" SP explanation-text)
# Example:
# 003cERR access denied or repository not exported: /foobarbaz
if (res =~ '^ERR ' && pathname >< res)
{
  register_service(port:port, proto:'git');
  security_note(port);
}
else
  audit(AUDIT_NOT_DETECT, 'git', port);
