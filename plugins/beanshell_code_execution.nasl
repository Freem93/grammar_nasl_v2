#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58975);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_name(english:"BeanShell Remote Server Mode Arbitrary Code Execution");
  script_summary(english:"Tries to execute Java code");

  script_set_attribute(
    attribute:"synopsis",
    value:"A shell is listening on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a BeanShell interpreter in remote server
mode.  This allows network clients to connect to the interpreter and
execute BeanShell commands and arbitrary Java code.  A remote,
unauthenticated attacker could exploit this to execute arbitrary
code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.beanshell.org/manual/remotemode.html");
  script_set_attribute(
    attribute:"solution",
    value:"Filter incoming traffic to this port or disable this service."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:beanshell_project:beanshell");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/BeanShell");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

port = get_service(svc:'BeanShell', exit_on_fail:TRUE);
soc = open_sock_tcp(port);
if (!soc)
  audit(AUDIT_SOCK_FAIL, port);

# ignored
banner = recv_line(socket:soc, length:1024);
prompt = recv_line(socket:soc, length:1024);

java = 'java.lang.System.getProperty("java.version")';
bsh = 'print(' + java + ');';
send(socket:soc, data:bsh + '\n');
ver = recv_line(socket:soc, length:1024);
ver = chomp(ver);
close(soc);

if (ver !~ '^[0-9._-]+$')
  audit(AUDIT_RESP_BAD, port);

if (report_verbosity > 0)
{
  report =
    '\nNessus executed the following BeanShell/Java code :\n\n' +
    bsh + '\n' +
    '\nWhich returned the following JRE version :\n\n' +
    ver + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

