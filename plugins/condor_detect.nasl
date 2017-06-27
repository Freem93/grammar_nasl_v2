#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34693);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_name(english:"Condor Service Detection");
  script_summary(english:"Queries status of various Condor services");

  script_set_attribute(attribute:"synopsis", value:"A grid-based computing service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Condor, an open source software framework
for distributed job scheduling.");
  script_set_attribute(attribute:"see_also", value:"http://www.cs.wisc.edu/condor/");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Condor_High-Throughput_Computing_System");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:condor_project:condor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 9618);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(9618);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (!silent_service(port)) exit(0, "The service listening on port "+port+" is not silent.");
}
else port = 9618;
if (known_service(port:port)) exit(0, "The service on port " + port + " has already been identified.");
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


# Define some constants.
DC_AUTHENTICATE = 60010;
DC_NOP = 60011;
QUERY_ANY_ADS = 48;

zero = mkbyte(0);


function make_classad(attrs, mytype, targettype)
{
  local_var ad, attr_name;

  if (isnull(mytype)) mytype = "(unknown type)";
  if (isnull(targettype)) targettype = "(unknown type)";

  ad = mkdword(max_index(keys(attrs)));
  foreach attr_name (sort(keys(attrs)))
    ad += attr_name + ' = ' + attrs[attr_name] + zero;
  ad += mytype + zero +
    targettype + zero;

  return ad;
}


function unmake_classad(classad)
{
  local_var attr, attr_name, attrs, expr, i, l, match, n, p;

  attrs = make_array();
  l = strlen(classad);
  n = getdword(blob:classad, pos:0);

  attr = "";
  p = 4;
  for (i=0; i<n && p<l; i++)
  {
    attr = substr(classad, p);
    if (zero >!< attr) return NULL;
    attr = attr - strstr(attr, zero);
    p += strlen(attr) + 1;

    match = eregmatch(pattern:"^(.+) = (.*)$", string:attr);
    if (!match) return NULL;

    attr_name = match[1];
    expr = match[2];
    attrs[attr_name] = expr;
  }

  attr = substr(classad, p);
  if (zero >!< attr) return NULL;
  attr = attr - strstr(attr, zero);
  p += strlen(attr) + 1;
  attrs['MyType'] = attr;

  attr = substr(classad, p);
  if (zero >!< attr) return NULL;
  attr = attr - strstr(attr, zero);
  p += strlen(attr) + 1;
  attrs['TargetType'] = attr;

  return attrs;
}


function condor_read(socket)
{
  local_var l, res1, res2;

  res1 = recv(socket:socket, length:5, min:5);
  if (strlen(res1) != 5) return NULL;
  # nb: from ReliSock::RcvMsg::rcv_packet() in condor_io/reli_sock.C
  if (
    getbyte(blob:res1, pos:0) < 0 ||
    getbyte(blob:res1, pos:0) > 10
  ) return NULL;

  l = getdword(blob:res1, pos:1);
  if (l <= 0 || l > 65535) return NULL;

  res2 = recv(socket:socket, length:l);
  if (l != strlen(res2)) return NULL;

  return res1+res2;
}


function condor_write(socket, buf, end)
{
  if (isnull(end)) end = 1;
  send(socket:socket, data:mkbyte(end)+mkdword(strlen(buf))+buf);
}


# Send a DaemonCore AUTHENTICATE command.
pid = rand() % 0xffff;
attrs = make_array(
  'AuthMethods', '"NTSSPI,KERBEROS"',
  'CryptoMethods', '"3DES,BLOWFISH"',
  'OutgoingNegotiation', '"PREFERRED"',
  'Authentication', '"OPTIONAL"',
  'Encryption', '"OPTIONAL"',
  'Integrity', '"OPTIONAL"',
  'Enact', '"NO"',
  'Subsystem', '"TOOL"',
  'ServerPid', pid,
  'SessionDuration', '"60"',
  'NewSession', '"YES"',
  'RemoteVersion', '"$CondorVersion: 7.0.4 Jul 16 2008 BuildID: 95033 $"',
  'Command', QUERY_ANY_ADS
);
auth_info = make_classad(attrs:attrs);

req = mkdword(0) +
      mkdword(DC_AUTHENTICATE) +
      mkdword(0) +
      auth_info;
condor_write(socket:soc, buf:req, end:1);
res1 = condor_read(socket:soc);
if (isnull(res1)) exit(0);
res2 = condor_read(socket:soc);
if (isnull(res2)) exit(0);


# If the response looks ok...
attr1s = unmake_classad(classad:substr(res1, 9));
attr2s = unmake_classad(classad:substr(res2, 9));
if (
  !isnull(attr1s) && !isnull(attr2s) &&
  attr1s['RemoteVersion'] &&  "$CondorVersion: " >< attr1s['RemoteVersion'] &&
  attr2s['ValidCommands']
)
{
  # Detect other associated services and collect info for the report.
  info = "";
  if (
    string(QUERY_ANY_ADS, ",") >< attr2s['ValidCommands'] ||
    string(",", QUERY_ANY_ADS) >< attr2s['ValidCommands']
  )
  {
    attrs = make_array(
      'Requirements', 'TRUE'
    );
    query = make_classad(attrs:attrs, mytype:"Query", targettype:"Any");
    req = mkdword(0) + query;
    condor_write(socket:soc, buf:req, end:1);

    res = condor_read(socket:soc);
    if (!isnull(res) && getdword(blob:res, pos:9) == 1 && getdword(blob:res, pos:13) == 0)
    {
      nop = str_replace(
        find:string("Command = ", QUERY_ANY_ADS),
        replace:string("Command = ", DC_NOP),
        string:auth_info
      );

      foreach classad (split(substr(res, 17), sep:mkdword(1)+mkdword(0), keep:FALSE))
      {
        attrs = unmake_classad(classad:classad);
        if (isnull(attrs)) continue;
        if (!attrs['MyType']) continue;

        type = attrs['MyType'];
        if (type == 'Scheduler' || type == 'DaemonMaster' || type == 'Negotiator')
        {
          if (report_verbosity)
          {
            info += '  - ' + type + ' :\n';
            foreach attr (sort(keys(attrs)))
              if (attr != 'MyType' && attr != 'TargetType')
                info += '    + ' + attr + ' = ' + attrs[attr] + '\n';
            info += '\n';
          }

          addr = attrs['MyAddress'];
          if (addr)
          {
            item = eregmatch(pattern:string("<", get_host_ip(), ":([0-9]+)>"), string:addr);
            if (isnull(item)) continue;

            alt_port = item[1];
            if (service_is_unknown(port:alt_port) && get_tcp_port_state(alt_port))
            {
              alt_soc = open_sock_tcp(alt_port);
              if (alt_soc)
              {
                alt_req = mkdword(0) +
                      mkdword(DC_AUTHENTICATE) +
                      mkdword(0) +
                      nop;
                condor_write(socket:alt_soc, buf:alt_req, end:1);
                alt_res1 = condor_read(socket:alt_soc);
                if (!isnull(alt_res1))
                {
                  alt_res2 = condor_read(socket:alt_soc);

                  alt_attr1s = unmake_classad(classad:substr(alt_res1, 9));
                  alt_attr2s = unmake_classad(classad:substr(alt_res2, 9));
                  if (
                    !isnull(alt_attr1s) && !isnull(alt_attr2s) &&
                    alt_attr1s['RemoteVersion'] &&  "$CondorVersion: " >< alt_attr1s['RemoteVersion'] &&
                    alt_attr2s['ValidCommands']
                  )
                  {
                    # Register and report the alternate service.
                    register_service(port:alt_port, proto:"condor_"+tolower(type));
                    security_note(port:alt_port, extra:'\nThe remote service is a Condor '+type+'.\n');
                  }
                }
                close(alt_soc);
              }
            }
          }
        }
      }
    }
  }

  # Register and report the service.
  register_service(port:port, proto:"condor_collector");

  if (report_verbosity && info)
  {
    report = string(
      "\n",
      "The remote service is a Condor Collector, and Nessus gathered the\n",
      "following information about selected Condor resources from it :\n",
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
close(soc);
