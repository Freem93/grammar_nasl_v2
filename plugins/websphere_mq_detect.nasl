#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(31411);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"IBM WebSphere MQ Listener Detection");
  script_summary(english:"Requests a connection to a queue manager");

  script_set_attribute(attribute:"synopsis", value:
"A messaging service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is an IBM WebSphere MQ Listener, responsible for
detecting connections from incoming MQ channels and routing them to a
queue manager.");
  script_set_attribute(attribute:"see_also", value:"http://www-306.ibm.com/software/integration/wmq/index.html");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/WebSphere_MQ");
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 1414);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

global_var qm_name, port;

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(1414);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0); 
}
else port = 1414;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

# Attempts to initiation a connection using the giving channel name.
#
# If the response doesn't look like Websphere MQ, this function will exit()
#
# returns TRUE if the channel_name given was valid,
#         FALSE otherwise
#
function request_conn(channel_name)
{
  local_var soc, req, res, valid_channel, segment_type, match;

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);
  valid_channel = FALSE;

  soc = open_sock_tcp(port);
  if (!soc) exit(0);
  
  req =                                   # ID
    "ID  " +
    mkbyte(4) +                           #   FAP level
    mkbyte(0x25) +                        #   flags (RUNTIME_APPLICATION|SERVER_CONNECTION_SECURITY|MQ_REQUEST|SPLIT_MESSAGES|CONVERSION_CAPABLE|MESSAGE_SEQ)
    mkbyte(0) +                           #   reserved
    mkbyte(0) +                           #   error flags
    mkword(0) +                           #   reserved
    mkword(0x32) +                        #   max messages per batch
    mkdword(0x7ffe) +                     #   maximum transmission size
    mkdword(0x064000) +                   #   maximum message size
    mkdword(0x3b9ac9ff) +                 #   sequence wrap value
    channel_name +                        #   channel name
      crap(data:" ", length:20-strlen(channel_name)) +
    mkword(0x0100) +                      #   flags
    mkword(0x0333) +                      #   character set
    crap(length:48, data:" ") +           #   queue manager
    mkdword(1) +                          #   heartbeat interval
    mkword(0);                            #   ??
  req = 
                                          # Transmission Segment Header
    string("TSH ") +                      #   magic
    mkdword(28+strlen(req)) +             #   segment LEN
    mkbyte(1) +                           #   byte order, 0x01 => big_endian
    mkbyte(1) +                           #   segment type, 0x01 => INITIAL_DATA
    mkbyte(0x31) +                        #   control flags (DQL_USED|REQ_ACCEPTED|LAST|FIRST|CLOSE|REQUEST_CLOSE|ERROR|Confirm_REQUEST)
    mkbyte(0) +                           #   reserved
    crap(data:mkbyte(0), length:8) +      #   logical unit of work identifier
    mkdword(0x0111) +                     #   encoding
    mkword(0x0333) +                      #   character set
    mkword(0) +                           #   padding
    req;
  send(socket:soc, data:req);
  res = recv(socket:soc, length:130, min:16);
  close(soc);
  
  # If...
  if (
    # it's long enough and...
    strlen(res) >= 10 &&
    # the packet starts with the magic string and...
    substr(res, 0, 3) == 'TSH ' &&
    # the packet is the right size
    getdword(blob:res, pos:4) == strlen(res)
  )
  {
    segment_type = getbyte(blob:res, pos:9);

    # get the QM name and remove any trailing whitespace
    match = eregmatch(string:qm_name, pattern:"^(.*[^ ]) *$");
    qm_name = substr(res, 76, 123);
  
    # the only expected responses are INITIAL_DATA (1) or STATUS_DATA (5).
    # If we see anything else, assume it isn't Websphere MQ and exit 
    if (segment_type == 1) valid_channel = TRUE;
    else if (segment_type != 5) exit(0);
  }
  else exit(0);

  return valid_channel;
}

#
# script execution begins here
#

# Only check using one channel unless the "Perform thorough tests" setting is enabled
channels = make_list("SYSTEM.DEF.SVRCONN");

if (thorough_tests)
  channels = make_list(channels, "SYSTEM.AUTO.SVRCONN", "SYSTEM.ADMIN.SVRCONN");

valid_channels = make_list();

foreach channel (channels)
{
  if(request_conn(channel_name:channel))
    valid_channels = make_list(valid_channels, channel);
}

# request_conn() will exit() if it sees a non-Websphere response, so if
# we made it this far, we successfully detected the service
register_service(port:port, proto:"websphere_mq");

if (report_verbosity && max_index(valid_channels) > 0)
{
  report = string(
    "Nessus detected the following queue manager name :\n\n",
    "  ", qm_name, "\n\n",
    "and verified it is available via the following channels :\n\n"
  );

  foreach channel (valid_channels)
    report += string("  ", channel, "\n");

  security_note(port:port, extra:report);
}
else security_note(port);
