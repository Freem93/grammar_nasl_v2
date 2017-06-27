#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29748);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/22 21:12:16 $");

  script_name(english:"Perforce Server Detection");
  script_summary(english:"Sends an 'info' command");

 script_set_attribute(attribute:"synopsis", value:
"A revision control system service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a Perforce server.  Perforce is a commercial,
proprietary revision control system, and a Perforce server manages a
central database to track file versions and user activity." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Perforce" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/23");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 1666);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(1666);
  if (!port) exit(0);
}
else port = 1666;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


function mk_block(data)
{
  local_var block, key, val;

  block = "";
  foreach key (keys(data))
  {
    val = data[key];
    block += key + mkbyte(0) + 
      mkdword(strlen(val)) + val + mkbyte(0);
  }
  block = mkbyte(strlen(block)) + 
    mkbyte(strlen(block)) + 
    mkbyte(0) + 
    mkbyte(0) +
    mkbyte(0) +
    block;
  return block;
}

function extract_data(block)
{
  local_var block_len, data, i, j, key, l, val;

  block_len = getbyte(blob:block, pos:0);
  if (block_len < 5 || block_len != strlen(block)-5) return NULL;

  data = make_array();
  i = 5;
  while (i < block_len)
  {
    j = stridx(block, mkbyte(0), i);
    if (j == -1) return NULL;
    key = substr(block, i, j-1);

    l = getdword(blob:block, pos:j+1);
    i = j+1+4;
    j = stridx(block, mkbyte(0), i);
    if (j == -1 || (j-i != l)) return NULL;
    if (l == 0) val = "";
    else val = substr(block, i, j-1);

    data[key] = val;
    i = j+1;
  }
  return data;
}


# Send an "info" command.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

user = "Nessus";
proto = make_array(
  "cmpfile", "",
  "client", "61",                      # client protocol (61 => 2007.2)
  "api", "99999",
  "func", "protocol"
);
cmd = make_array(
  "prog", "p4",
  "version", "2007.1/NTX86/123456",
  "client", "nessus",
  "cwd", "c:\Program Files\Perforce",
  "host", this_host_name(),
  "os", "NT",
  "user", user,
  "func", "user-info"
);

req = mk_block(data:proto) + mk_block(data:cmd);
send(socket:soc, data:req);
res = recv(socket:soc, length:4096, min:4);
close(soc);


# If ...
if (
  # the response is long-enough and ...
  getbyte(blob:res, pos:0) <= strlen(res) &&
  # it reports a server level and...
  ("server2"+mkbyte(0)) >< res &&
  # it contains a protocol message and ...
  ("func"+mkbyte(0)+mkdword(8)+"protocol"+mkbyte(0)) >< res
)
{
  # Gather some info for the report.
  info = "";

  while (strlen(res))
  {
    len = getbyte(blob:res, pos:0);
    block = substr(res, 0, len+4);
    data = extract_data(block:block);
    if (isnull(data)) break;

    if (data["server2"])
    {
      level = data["server2"];
      set_kb_item(name:"Perforce/"+port+"/Level", value:level);
      info += '  Server protocol : ' + level + '\n';
    }
    else if (data["fmt0"])
    {
      fmt = data["fmt0"];
      fmt = str_replace(find:":", replace:" :", string:fmt);
      while (fmt =~ "%[^%]+%")
      {
        match = ereg_replace(pattern:"^.*%([^%]+)%.*$", replace:"\1", string:fmt);
        if (match)
        {
          if (isnull(data[match])) val = "(NULL)";
          else
          {
            val = data[match];
            if (match == "id") set_kb_item(name:"Perforce/"+port+"/Version", value:val);
          }
        }
        else val = "(NULL)";
        fmt = str_replace(find:"%"+match+"%", replace:val, string:fmt);
      }
      if (fmt !~ "^(Client|User name)") info += '  ' + fmt + '\n';
    }

    res = res - block;
  }

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"perforce");

  if (report_verbosity && info)
  {
    report = string(
      "\n",
      "Here is some information about the remote Perforce server that Nessus\n",
      "was able to collect :\n",
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
