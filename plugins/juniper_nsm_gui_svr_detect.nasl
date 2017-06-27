#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69870);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 16:49:07 $");

  script_name(english:"Juniper NSM GUI Server Detection");
  script_summary(english:"Detects NSM GUI Server");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is running a remote administration service."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running the Juniper NSM GUI Server.  The NSM GUI
accepts connections from users using the NSM GUI Client, which allows
for administration of the NSM servers."
  );
  # http://www.juniper.net/us/en/products-services/software/network-management-software/nsm/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11d258f7");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:netscreen-security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 7808);
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}

include('audit.inc');
include('byte_func.inc');
include('global_settings.inc');
include('misc_func.inc');

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# This plugin gets the version information by making a bogus login
# attempt. It can cause an IP to be blocked for an hour if several
# unsuccessful attempts are made (10 by default).
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Unless paranoid, before making any requests, make sure
# the host is not running Windows. NSM only runs on Solaris
# or RHEL
if (report_paranoia < 2 && os = get_kb_item('Host/OS'))
{
  if ('Linux' >!< os && 'Solaris' >!< os) audit(AUDIT_HOST_NOT, 'Unix/Linux');
}

port = get_unknown_svc(7808);

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port_known = get_unknown_svc(port);
  if (!port_known) audit(AUDIT_SVC_KNOWN);
}

if (known_service(port:port)) audit(AUDIT_SVC_KNOWN);
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

if (!get_port_state(port)) audit(AUDIT_NOT_LISTEN, "Junipers NSM GUI Server", port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

encaps = get_port_transport(port);

login_req =
'\x03\x00\x00\x00' + # constant
'\x00\x00\x00\x01' + # seq
'\x01' + # start of data
'authManager' + # module
'\x00' +
# command string
'(authManager\n' +
  ':command (authenticate):request (\n' +
  ':userName (nessus):password (bad_password):domainName (global):protocolVersion (bogus_protocol)))' +
'\x00'; # end of data

# prepend length
login_req = mkdword(strlen(login_req)) + login_req;

send(socket:soc, data:login_req);

temp = recv(socket:soc, length:4);

data_len = getdword(blob:temp, pos:0);

# sanity check
if (data_len > 10 * 1024 || data_len <= 16)
{
  close(soc);
  audit(AUDIT_NOT_INST, "Juniper NSM GUI Server");
}

data = recv(socket:soc, length:data_len);
if (strlen(data) != data_len)
{
  close(soc);
  audit(AUDIT_NOT_INST, "Juniper NSM GUI Server");
}

if (
   # blocked notification
   ("guiNotification" >!< data || "SYSTEM.blockedIPList" >!< data) &&
   # general auth response
   (":authStatus (" >!< data || "(authManager" >!< data ||
    ":status (" >!< data || ":response (" >!< data)
)
{
  close(soc);
  audit(AUDIT_NOT_INST, "Juniper NSM GUI Server");
}

register_service(port:port, ipproto:"tcp", proto:"juniper_nsm_gui_svr");

disp_version = "unknown";

response = substr(data,12,strlen(data)-4);

# save the response
set_kb_item(name:"Juniper_NSM_GuiSvr/" + port + "/auth_response",
            value:response);

# unless we are blocked, we should get a helpful
# response which tells us what client version we
# *should* be using, and even where we may go to
# download it
ver_item = eregmatch(pattern: 'server version:[ ]*([^"]+)"',
                     string: response);
build_item = eregmatch(pattern: "guiSvrBuild[ ]*\(([^\)]+)\)",
                       string: response);

if (!isnull(ver_item) && !isnull(build_item))
{
  set_kb_item(name:"Juniper_NSM_GuiSvr/" + port + "/version",
              value:ver_item[1]);
  set_kb_item(name:"Juniper_NSM_GuiSvr/" + port + "/build",
              value:build_item[1]);
  replace_kb_item(name:"Juniper_NSM_VerDetected", value:TRUE);

  disp_version = ver_item[1] + " (Build: " + build_item[1] + ")";
}

report = '\n  Version : ' + disp_version;

if (report_verbosity > 1)
  report += '\n  Server response :\n\n' +
            crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n'+
            chomp(response) + '\n' +
            crap(data:"-", length:30)+" snip "+crap(data:"-", length:30);

report += '\n';

if (report_verbosity > 0) security_note(extra:report, port:port);
else security_note(port);
