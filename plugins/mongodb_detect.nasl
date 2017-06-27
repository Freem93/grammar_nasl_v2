#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65914);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/03/12 14:46:00 $");

  script_name(english:"MongoDB Detection");
  script_summary(english:"Detects MongoDB");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a database system.");
  script_set_attribute(attribute:"description", value:"A document-oriented database system is listening on the remote port.");
  script_set_attribute(attribute:"see_also", value:"http://www.mongodb.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_require_ports("Services/unknown", 27017);
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = NULL;

MONGODB_PROTO = "mongodb";
mongodb_detected = FALSE;

# default listening port for mongodb
port_list = make_list(27017);

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  unknown_services = get_unknown_svc_list();
  port_list = make_list(port_list, unknown_services);
}

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# filter out duplicate ports
port_list = list_uniq(port_list);

function size_encapsulate(data)
{
  return mkdword(strlen(data) + 4) + data;
}

function recv_response(sock)
{
  local_var size, data;
  data = recv(socket:sock, min:4, length:4);

  if (isnull(data) || strlen(data) != 4)
    return NULL;

  size = getdword(blob:data, pos:0);
  if(size > 10*1024*1024) return NULL;

  # message should contain some data
  if (size <= 4) return NULL;

  data = recv(socket:sock, min:size - 4, length:size - 4);

  if (isnull(data) || strlen(data) != (size - 4))
    return NULL;

  return data;
}

function build_query(collection, bson, request_id)
{
  local_var query;
  if (isnull(request_id) || strlen(request_id) != 4)
    request_id = "ness";

  query =
  request_id + # request id (4 bytes)
  raw_string(0x00, 0x00, 0x00, 0x00) + # responseTo
  raw_string(0xd4, 0x07, 0x00, 0x00) + # query
  raw_string(0x00, 0x00, 0x00, 0x00) + # flags
  collection + raw_string(0x00) + # collection name
  raw_string(0x00, 0x00, 0x00, 0x00) + # number of records to skip
  raw_string(0xff, 0xff, 0xff, 0xff) + # number to return
  bson;
  query = size_encapsulate(data: query);

  return query;
}

# For each of the ports we want to try, fork.
port = branch(port_list);

if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

ismaster_command =
  raw_string(0x10) + # int32
  "ismaster" + raw_string(0x00) + # command
  raw_string(0x01, 0x00, 0x00, 0x00) + # 1
  raw_string(0x00); # end BSON document
ismaster_command = size_encapsulate(data: ismaster_command);

buildinfo_command =
  raw_string(0x10) + # int32
  "buildinfo" + raw_string(0x00) + # command
  raw_string(0x01, 0x00, 0x00, 0x00) + # 1
  raw_string(0x00); # end bson document
buildinfo_command = size_encapsulate(data: buildinfo_command);

query_ismaster = build_query(collection:'admin.$cmd',
                             request_id: 'nes1',
                             bson:ismaster_command);

query_buildinfo = build_query(collection:'admin.$cmd',
                              request_id: 'nes2',
                              bson:buildinfo_command);

# ismaster command should return regardless of authentication
send(socket:soc, data:query_ismaster);

response = recv_response(sock:soc);

if (isnull(response))
{
  close(soc);
  audit(AUDIT_NOT_LISTEN, "MongoDB", port);
}

if (
  'nes1' >!< response ||
  'maxBsonObjectSize' >!< response ||
  'ismaster' >!< response
)
{
  close(soc);
  audit(AUDIT_NOT_LISTEN, "MongoDB", port);
}

version = 'unknown';

# try to get version, buildinfo command should run without
# auth on almost every version (2.0.0 is a known exception)
send(socket:soc, data:query_buildinfo);

response = recv_response(sock:soc);

close(soc);

version_tag = raw_string(0x02, # str identifier
                         0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, # 'version'
                         0x00);

git_version_tag = raw_string(0x02, # str identifier
                             0x67, 0x69, 0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, # 'gitVersion'
                             0x00);

ver_str = NULL;
if (!isnull(response) && version_tag >< response)
{
  ver_offset = stridx(response, version_tag) + strlen(version_tag);
  ver_str_len = getdword(blob:response, pos:ver_offset);
  if (
    ver_offset+4+ver_str_len-2 <= strlen(response) &&
    ver_str_len > 0 && !isnull(ver_str_len)
  ) ver_str = substr(response, ver_offset+4, ver_offset+4+ver_str_len-2);
}

git_ver_str = NULL;
if (!isnull(response) && git_version_tag >< response)
{
  git_ver_offset = stridx(response, git_version_tag) + strlen(git_version_tag);
  git_ver_str_len = getdword(blob:response, pos:git_ver_offset);
  if (
    git_ver_offset+4+git_ver_str_len-2 <= strlen(response) &&
    git_ver_str_len > 0 || !isnull(git_ver_str_len)
  ) git_ver_str = substr(response, git_ver_offset+4, git_ver_offset+4+git_ver_str_len-2);
}

if (!isnull(ver_str)) version = ver_str;

mongodb_detected = TRUE;
register_service(port:port, ipproto:"tcp", proto:MONGODB_PROTO);

report = '\n  Version     : ' + version;
set_kb_item(name:'mongodb/' + port + '/Version', value: version);

if (!isnull(git_ver_str))
{
   set_kb_item(name:'mongodb/' + port + '/GitVersion', value: git_ver_str);
   report += '\n  Git version : ' + git_ver_str;
}
report += '\n';

if (version == 'unknown')
{
  report = '\nUnable to obtain version information for MongoDB instance.\n';
  security_note(port:port, extra:report);
}
else
  security_note(port:port, extra:report);

if (!mongodb_detected)
  audit(AUDIT_NOT_INST, "MongoDB");
else
  replace_kb_item(name:"mongodb", value:TRUE);
