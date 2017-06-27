#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51094);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_name(english:"DiskPulse Server Default Credentials");
  script_summary(english:"Test the default username and password ('diskpulse'/'diskpulse') against a DiskPulse server.");

  script_set_attribute(attribute:"synopsis", value:"The remote service is protected using default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the DiskPulse server with the default
username and password ('diskpulse'/'diskpulse').

This could allow an attacker to view and change the DiskPulse
configuration and the server itself.");
  script_set_attribute(attribute:"see_also", value:"http://www.diskpulse.com/diskpulse_server.html");
  script_set_attribute(attribute:"solution", value:
"Change the default password on the DiskPulse server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies('diskpulse_detect.nasl');
  script_require_ports('Services/diskpulse', 9120);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

function read_token(str, separator)
{
  local_var i, result;

  result = '';
  for(i = 0; str[i] != separator; i++)
  {
    if(i > strlen(str))
      exit(0, "Couldn't deserialize DiskPulse string");

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


# Get the port
port = get_service(svc:'diskpulse', default:9120, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Open the socket
socket = open_sock_tcp(port);
if (!socket) audit(AUDIT_SOCK_FAIL, port);

# Build the GetServerInfo request

# Header
request = marshall_header(name:"ServerLogin", seq:"000000080");

# Body
body = make_array(
  'ClientHostName', 'nessus',
  'UserName', 'diskpulse',
  'Password', 'diskpulse'
);
request = request + marshall_body(fields:body);

# Send our packet
send(socket:socket, data:request);

# Receive 512 bytes back (should be 'OK' then 510 bytes of nonsense)
response = recv(socket:socket, length:512, min:512);
if (isnull(response)) exit(0, "The service on port "+port+" failed to respond.");
if (strlen(response) < 512) exit(0, "The service on port "+port+" responded with less than 512 bytes.");
if (substr(response, 0, 1) != "OK") exit(0, "The service on port "+port+" failed to respond with an 'OK'.");

# Receive the next 512 bytes back - this one should have the 'OK', as usual,
# as well as a serialized SCA_ConfigObj object.
response = recv(socket:socket, length:512, min:512);
if (isnull(response)) exit(0, "The service on port "+port+" failed to respond.");
if (strlen(response) < 512) exit(0, "The service on port "+port+" responded with less than 512 bytes.");

# The header starts at the beginning
header = unmarshall_header(data:response);

# Verify that the result is what we wanted
if (header['result'] != 'OK') exit(0, "The service on port "+port+" failed to respond with an 'OK'.");

# The marshalled object starts at 0x2c
body = unmarshall_body(data:substr(response, 0x2c));

if (isnull(body['Status'])) exit(0, "The DiskPulse Server listening on port "+port+" didn't return a status.");

if (body['Status'] == '1') security_hole(port);
else exit(0, "The DiskPulse Server listening on port "+port+" doesn't appear to use default credentials.");


