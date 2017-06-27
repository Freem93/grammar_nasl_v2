#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67022);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/28 18:48:35 $");

  script_name(english:"Hazelcast Wire Protocol Detection");
  script_summary(english:"Detects Hazelcast");

  script_set_attribute(attribute:"synopsis", value:"A listening data clustering service was detected.");
  script_set_attribute(
    attribute:"description",
    value:
"The wire protocol for Hazelcast, an open source data clustering
solution, was found listening on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.hazelcast.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hazelcast:hazelcast");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("hazelcast_rest_detect.nasl");
  script_require_ports("Services/unknown", "Services/www", 5701);
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = NULL;

HAZELCAST_PROTO = "hazelcast";

# default listening port for hazelcast
port_list = make_list(5701);

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  unknown_services = get_unknown_svc_list();
  port_list = make_list(port_list, unknown_services);
}

www_port_list = get_kb_list('hazelcast/*/rest');
foreach item (keys(www_port_list))
  port_list = make_list(port_list, int(item - 'hazelcast/' - '/rest'));

# filter out duplicate ports
port_list = list_uniq(port_list);

function recv_response(sock)
{
  local_var size, data, hdr_size, data_size, hdr_data, message_data,
            ret_val;
  data = recv(socket:sock, min:12, length:12);

  if (isnull(data) || strlen(data) != 12)
    return NULL;

  hdr_size = getdword(blob:data, pos:0) + 1;
  data_size = getdword(blob:data, pos:8);

  # sanity check
  if (hdr_size > (1024*10) || data_size > (1024*10)) return NULL;

  if (hdr_size <= 0) return NULL;

  hdr_data = recv(socket:sock, min:hdr_size, length:hdr_size);
  if (isnull(hdr_data) || strlen(hdr_data) != (hdr_size))
    return NULL;

  data = '';
  if (data_size > 0)
  {
    message_data = recv(socket:sock, min:data_size, length:data_size);
    if (isnull(message_data) || strlen(message_data) != (data_size))
      return NULL;
  }

  ret_val = make_array();
  ret_val['message_size'] = data_size;
  ret_val['message_data'] = message_data;
  ret_val['hdr_size'] = hdr_size;
  ret_val['hdr_data'] = hdr_data;
  return ret_val;
}

# For each of the ports we want to try, fork.
port = branch(port_list);

if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# detect newer 3.0 alpha version
hazelcast_detected = FALSE;

send(socket:soc, data:'version\r\n');
res = recv(socket:soc, length:1024);
close(soc);

if (!isnull(res) && res =~ "^VERSION Hazelcast")
{
  register_service(port:port, ipproto:"tcp", proto:HAZELCAST_PROTO);

  replace_kb_item(name:"hazelcast", value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\nThe hazelcast service on port ' + port + ' responded to the "version"' +
             '\ncommand with the following :\n' +
             '\n  ' + chomp(res) + '\n';
   security_note(extra:report, port:port);
  }
  else security_note(port);
  exit(0);
}

hazelcast_banner_detected = TRUE;

foreach protocol_version (make_list('4a','5c','8a','7a','6a','6b','6c','6d','5a',
                                    '5b'))
{
  if (!get_tcp_port_state(port))
    audit(AUDIT_PORT_CLOSED, port);

  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  socket_set_timeout(socket:soc, timeout:3);

  variant = protocol_version[1];
  protocol_version = int(protocol_version[0]);

  if (
    protocol_version > 5 ||
    (protocol_version == 5 && variant != 'c')
  )
  {
    send(socket:soc, data:'HZC');

    res = recv(socket:soc, min:3, length:3);

    if (isnull(res) || res != 'HZC')
    {
      close(soc);
      continue;
    }
  }

  login_req = '';
  header = '';
  data = '';
  key_data = '';
  extra_data = '';

  header += mkbyte(protocol_version);

  # operation - CLIENT_AUTHENTICATE
  if (protocol_version == 6)
    if (variant == 'b')
      header += '\x61';
    else if (variant == 'd')
      header += '\x5c';
    else
      header += '\x53';
  else if (protocol_version == 5)
    if (variant == 'a')
      header += '\x04';
    else header += '\x03';
  else if (protocol_version == 4)
    header += '\x03';
  else
    header += '\x00\x87';

  if (protocol_version <= 5)
  {
    header +=
    '\x00\x00\x00\x00' + # thread id
    '\x00\x00\x00\x00';  # block id
  }
  else
  {
    header +=
    '\xff\xff\xff\xff' + # block id (-1)
    '\x00\x00\x00\x00';  # thread id
  }

  header +=
    '\xd0' + # booleans
    '\x00\x00\x00\x00\x00\x00\x00\x00';
  if (protocol_version == 4)
    header += '\x00\x00\x00\x00\x00\x00\x00\x02';
  else
    header +=
    '\xff\xff\xff\xff\xff\xff\xff\xff'; # callid

  header += '\x02'; # RESPONSE_NONE

  # build out data section of message
  if (protocol_version <= 5)
  {
    header +=
    '\x00\x00\x00\x0f' + # name length
    'remotelyProcess' + # name
    '\x00';

    data +=
    '\x00\x00\x00\x00\x01\x00\x1a' +
    'com.hazelcast.cluster.Bind' +
    '\xac\x1a\x16\x1f\x00\x00';

    if (protocol_version == 4)
      data += '\xc8\x75';
  }
  if (protocol_version == 5)
  {
    if (variant == 'a')
    {
      data += '\xc9\x24';
      extra_data +=
      '\x00\x00\x00\x20\x00\x00\x00\x0a\x00\x00\x00' +
      '\x0f\x05\x51\x00\x00\x00\x00\x00\x00\x00\x01\xd0\x00';
    }
    else
    {
      data += '\xc8\x75';
      extra_data +=
      '\x00\x00\x00\x20\x00\x00\x00\x0a\x00\x00'+
      '\x00\x0f\x05\x4a\x00\x00\x00\x00\x00\x00\x00\x01\xd0\x00';
    }
    extra_data +=
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02' +
    '\x00\x00\x00\x00\x00\x06\x00\x00\x00\x01\x00\x03' +
    'dev' +
    '\x06\x00\x00\x00\x01\x00\x08' +
    'dev-pass';
  }
  else if (protocol_version > 5)
  {
    header +=
    '\x00\x00\x00\x00\x00'; # name length

    if (protocol_version == 6)
    {
      if (variant == 'a' || variant == 'd')
      {
        key_data +=  '\x01\x05\x00\x00' +
                     '\x00\x01\x00\x03' +
                     'dev';

        data +=      '\x01\x05\x00\x00' +
                     '\x00\x01\x00\x08' +
                     'dev-pass';
      }
      else if (variant == 'b')
      {
        header += '\xff\xff\xff\xff' + # hashes
                  '\xff\xff\xff\xff';

        key_data +=
        '\x01\x05\x00\x00\x00\x00\x03\x00\x03' +
        'dev';

        data +=
        '\x01\x05\x00\x00\x00\x00\x08\x00\x08' +
        'dev-pass';
      }
      else if (variant == 'c')
      {
        key_data += '\x06\x00\x00\x00\x01\x00\x03' +
                     'dev';

        data += '\x06\x00\x00\x00\x01\x00\x08' +
                'dev-pass';
      }
    }
    else
    {
      header += '\xff\xff\xff\xff' + # key hash
                '\xff\xff\xff\xff';  # value hash

      data +=
      # serialized login request
      '\x00\x00\x00\x00\x00\x00\x32\x00\x32' +
      'com.hazelcast.security.UsernamePasswordCredentials' +
      '\x00\x00\x00\x00\x03\x00\x03' +
      'dev' + # default pass
      '\x01\x00\x00\x00\x08' +
      'dev-pass'; # default password
    }
  }

  if (protocol_version <= 6)
    login_req = mkdword(strlen(header) - 1) + mkdword(strlen(key_data)) + mkdword(strlen(data));
  else
    login_req = mkdword(strlen(header)) + mkdword(strlen(key_data)) + mkdword(strlen(data) - 1);

  login_req += header                  + key_data                  + data +
               extra_data;

  send(socket:soc, data:login_req);

  response = recv_response(sock:soc);
  if (protocol_version == 4 && !isnull(response))
  {
    cred_message =
    '\x00\x00\x00\x20' + # header_len
    '\x00\x00\x00\x0a' + # key size
    '\x00\x00\x00\x0f' + # data size
    '\x04' + # proto ver
    '\x4a' + # operation
    '\x00\x00\x00\x00' +
    '\x00\x00\x00\x01' +
    '\xd0' + # booleans
    '\x00\x00\x00\x00\x00\x00\x00\x00' +
    '\x00\x00\x00\x00\x00\x00\x00\x01' + # callid
    '\x02' +  # RESPONSE_NONE
    '\x00\x00\x00\x00' + # key name len
    '\x00' +
    '\x06\x00\x00\x00\x01\x00\x03' + # key
    'dev' +
    '\x06\x00\x00\x00\x01\x00\x08' + # value
    'dev-pass';
    send(socket:soc, data:cred_message);
    response = recv_response(sock:soc);
  }

  if ('java.lang.Boolean' >!< response['message_data'] &&
     protocol_version == 5)
    response = recv_response(sock:soc);

  close(soc);

  if (isnull(response))
    continue;

  message_size = response['message_size'];
  message_data = response['message_data'];

  if (
     'java.lang.Boolean' >< message_data
     ||
     (message_size ==  3 &&
      message_data[0] == '\x01' &&
      message_data[1] == '\x09'))
  {
    hazelcast_detected = TRUE;
    break;
  }
}

if (!hazelcast_detected)
  audit(AUDIT_NOT_LISTEN, "Hazelcast", port);

set_kb_item(name:'hazelcast/' + port + '/protocol_version', value:protocol_version);
set_kb_item(name:'hazelcast/' + port + '/protocol_variant', value:variant);

register_service(port:port, ipproto:"tcp", proto:HAZELCAST_PROTO);

replace_kb_item(name:"hazelcast", value:TRUE);

if (report_verbosity > 0)
{
  report = '\nHazelcast wire protocol version ' + protocol_version + ' detected on port ' + port + '.\n';
  security_note(extra:report, port:port);
}
else security_note(port);
