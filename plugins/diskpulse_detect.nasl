#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51093);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/01/25 16:35:58 $");

  script_name(english:"DiskPulse Server Detection");
  script_summary(english:"DiskPulse Server detection");

  script_set_attribute(
    attribute:"synopsis",
    value:"A filesystem monitoring service is listening on this port."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a DiskPulse Server, a tool that monitors
changes to the filesystem and reports them to all authenticated
clients."
  );

  script_set_attribute(attribute:"see_also", value:"http://www.diskpulse.com/diskpulse_server.html" );
  script_set_attribute(attribute:"solution", value: "Disable this service if you do not use it." );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 9120);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

function read_token(str, separator)
{
  local_var i, result;

  result = '';
  for(i = 0; str[i] != separator; i++)
  {
    if(i > strlen(str))
      exit(0, "Couldn't deserialize DiskPulse string.");

    result = result + str[i];
  }

  return result;
}

function marshall_header(name, seq)
{
  local_var result;
  result = '';

  result = result + name + '\x02';
  result = result + seq  + '\x02';

  # Pad the header to exactly 0x2c bytes
  result = result + crap(data:'\x02', length:(0x2c - strlen(result))); # Pad the header to 0x2c bytes

  return result;
}

function unmarshall_header(data)
{
  local_var result;

  result = make_array();

  result['result'] = read_token(str:data, separator:'\x02');
  data = substr(data, strlen(result['result'])+1);

  result['seq'] = read_token(str:data, separator:'\x02');
  data = substr(data, strlen(result['seq'])+1);

  return result;
}

function marshall_body(fields)
{
  local_var result, key;
  result = '';

  # Add the version number
  result = result + '2\x01';

  # Add the string 'Data'
  result = result + 'Data\x01';

  # Add the number of fields
  if(isnull(fields) || !max_index(keys(fields)))
    result = result + '0\x01';
  else
  {
    result = result + string(max_index(keys(fields))) + '\x01';

    foreach key(keys(fields))
    {
      result = result + '1\x01'; # Unknown
      result = result + key + '\x01';
      result = result + fields[key] + '\x01';
    }
    result = result + '\x00';
  }

  # Pad the body to exactly 468 bytes (that's 0x200 - the header's 0x2c)
  result = result + crap((0x200 - 0x2c - strlen(result)));

  return result;
}

function unmarshall_body(data)
{
  local_var result, i, count, unknown, name, value;

  result = make_array();

  result['version'] = read_token(str:data, separator:'\x01');
  data = substr(data, strlen(result['version'])+1);

  result['header'] = read_token(str:data, separator:'\x01');
  data = substr(data, strlen(result['header'])+1);

  result['count'] = read_token(str:data, separator:'\x01');
  data = substr(data, strlen(result['count'])+1);


  # Now loop 'count' times and parse the fields/values. 
  count = int(result['count']);
  for(i = 0; i < count; i++)
  {
    unknown = read_token(str:data, separator:'\x01');
    data = substr(data, strlen(unknown)+1);

    name = read_token(str:data, separator:'\x01');
    data = substr(data, strlen(name)+1);

    value = read_token(str:data, separator:'\x01');
    data = substr(data, strlen(value)+1);

    result[name] = value;
  }

  return result;
}

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(9120);
  if (!port) exit(0, "There are no unknown services.");
}
else port = 9120;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (!get_tcp_port_state(port)) exit(1, "Port "+port+" is not open.");

socket = open_sock_tcp(port);
if (!socket) exit(1, "Can't open socket on port "+port+".");

# Marshall the header
request = marshall_header(name:"GetServerInfo", seq:"000000010");

# Body
request = request + marshall_body(fields:NULL);

# Send our packet
send(socket:socket, data:request);

# Receive 512 bytes back (should be 'OK' then 510 bytes of nonsense)
response = recv(socket:socket, length:512, min:512);
if (isnull(response)) exit(0, "The service on port "+port+" failed to respond.");
if (strlen(response) < 512) exit(0, "The service on port "+port+" responded with less than 512 bytes.");
if (substr(response, 0, 1) != "OK") exit(0, "The service on port "+port+" can't be identified as DiskPulse.");

# Receive the next 512 bytes back - this one should have the 'OK', as usual, 
# as well as a serialized SCA_ConfigObj object. 
response = recv(socket:socket, length:512, min:512);
if (isnull(response)) exit(0, "The service on port "+port+" failed to respond.");
if (strlen(response) < 512) exit(0, "The service on port "+port+" responded with less than 512 bytes.");

# The header starts at the beginning
header = unmarshall_header(data:response);

# Verify that the result is what we wanted
if (header['result'] != 'OK') exit(0, "The service on port "+port+" returned an error.");

# The marshalled object starts at 0x2c
body = unmarshall_body(data:substr(response, 0x2c));

# Any valid DiskPulse server will return its ServerVersion here
if (isnull(body['ServerVersion'])) exit(1, "The response from port "+port+" doesn't contain a version number.");

# Save the version
set_kb_item(name:"diskpulse/"+port+"/version", value:body['ServerVersion']);
register_service(port:port, ipproto:"tcp", proto:"diskpulse");

# Report the service
if (report_verbosity > 0) security_note(port:port, extra:'\n  Version : ' + body['ServerVersion'] + '\n');
else security_note(port);
