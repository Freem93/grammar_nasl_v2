#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30207);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_name(english:"LPD Detection");
  script_summary(english:"Sends various LPD commands");

  script_set_attribute(
    attribute:"synopsis",
    value:"A printer service is listening on the remote host."
  );
  script_set_attribute( attribute:"description", value:
"The remote service supports the line printer daemon (lpd) protocol,
which is widely-used by print servers."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://tools.ietf.org/html/rfc1179"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Limit incoming traffic to this port if desired."
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2008/02/08"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 515);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(515);
  if (!port) exit(0);
}
else port = 515;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


# Query a print queue.
queue = string("nessus-", unixtime());

soc = open_priv_sock_tcp(dport:port);
if (!soc) exit(0);

req = mkbyte(4) + queue + " " + mkbyte(0x0a);
send(socket:soc, data:req); 
res = recv(socket:soc, length:1024, min:1);
close(soc);


# If it looks like a valid response...
if (strlen(res))
{
  lres = tolower(res);
  if (
    "not open status file for the given print queue" >< lres ||
    "lpd: printer not found" >< lres ||
    "no entries" >< lres ||
    "no jobs queued" >< lres ||
    string(queue, ": unknown printer") >< lres ||
    string("queue '", queue, "' is empty.") >< lres ||
    "printer device:" >< lres ||
    "printer is paused" >< lres ||
    "printer is ready" >< lres ||
    "printer status:" >< lres
  )
  {
    # Register and report the service.
    register_service(port:port, proto:"lpd");

    security_note(port);
    exit(0);
  }
}


# Try printing any waiting jobs for our queue.
#
# nb: some servers only provide a a single-byte response to this.
soc = open_priv_sock_tcp(dport:port);
if (!soc) exit(0);

req = mkbyte(1) + queue + " " + mkbyte(0x0a);
send(socket:soc, data:req); 
res = recv(socket:soc, length:64, min:1);
close(soc);


# If the response looks right...
if (
  strlen(res) &&
  (getbyte(blob:res, pos:0) == 0 || getbyte(blob:res, pos:0) == 1) &&
  (
    "Invalid queue" >< res ||
    (strlen(res) == 1 && report_paranoia > 1)
  )
)
{
  # Register and report the service.
  register_service(port:port, proto:"lpd");

  if (report_verbosity && strlen(res) == 1 && report_paranoia > 1)
  {
    note = string(
      "\n",
      "Note that Nessus only received a single byte in response to a command\n",
      "to print any waiting jobs for a queue.  While this method is not\n",
      "completely reliable, Nessus used it because the Report Paranoia\n",
      "setting in effect when this scan was run was set to 'Paranoid'.\n"
    );
    security_note(port:port, extra:note);
  }
  else security_note(port);
}
