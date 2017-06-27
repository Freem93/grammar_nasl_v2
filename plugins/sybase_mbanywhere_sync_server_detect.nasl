#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54617);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/05/24 02:04:27 $");

  script_name(english:"Sybase M-Business Anywhere (AvantGo) Sync Server Detection");
  script_summary(english:"Checks for response from the Sync Server");

  script_set_attribute(
    attribute:"synopsis",
    value:"A mobile application service is listening on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service is a Sybase M-Business Anywhere (formerly AvantGo)
Sync Server, which handles synchronization requests from a mobile
device and determines whether to obtain requested pages from the
source web server or from a shared cache on the Sync Server itself."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.sybase.com/products/allproductsa-z/m-businessanywhere"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/23");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("http.inc");
include("dump.inc");


#
# some AG (AvantGo) commands
# commands must be btw 0 and 0x49
#
AG_END_CMD        = 0x00;
AG_EXPANSION_CMD  = 0x01;
AG_HELLO_CMD      = 0x02;
AG_PING_CMD       = 0x13;


AG_MAGIC          = '\xda\x7e';


##
# converts an integer into a compact(variable-length) integer
# 
# @anonparam an integer
# @return formatted compact integer in raw string representation
# 
##
function cint_encode()
{
  local_var v;
  
  v = uint(_FCT_ANON_ARGS[0]);
  
  if (v < 0xFE)
    return mkbyte(v);
  else if (v < 0x10000)
    return mkbyte(0xFE) + mkword(v);
  else
    return mkbyte(0xFF) + mkdword(v);
}

##
# decodes a compact integer  
#
# @param blob  - data stream to read from
# @param pos   - starting position to read
# 
# @return ret['value'] - decoded integer value
#         ret['len']   - number of bytes consumed to produce a decoded value
##
function cint_decode(blob, pos)
{
  local_var v, ret, dlen, spos;
  
  dlen = strlen(blob);
  
  if (dlen < 1) return NULL;
  
  if (isnull(pos)) pos = 0;
  spos = pos;
  
  # int8
  v = getbyte(blob:blob, pos:pos); pos++;
  
  # int16
  if (v == 0xFE)
  {
    if (dlen < 3) return NULL;
    v = getword(blob:blob, pos:pos);
    pos += 2;
  }
  # int32
  else if (v == 0xFF) 
  {
    if (dlen < 5) return NULL;
    v = getdword(blob:blob, pos:pos);
    pos += 4;
  }
    
  ret['value'] = v;
  ret['len']   = pos - spos;
  
  return ret;
}


##
# creates a command
#
# @param cmd        - one-byte command code
# @param parmams    - command parameters
# @return  formatted ag command structure
##
function ag_cmd(cmd, params)
{
  if (isnull(params))
    return mkbyte(cmd) + '\x00'; 
  else
    return mkbyte(cmd) + cint_encode(strlen(params)) + params;
}

##
#
# checks if the response is an AvantGo PDU
#
# @anonparam HTTP response data
# @return 1 if it's a AvantGo PDU
#         0 if it's not a AvantGo PDU
#
##
function ag_pdu_check()
{
  local_var data, magic, ret,pos, dlen, cmd, params, params_len;
  
  data = _FCT_ANON_ARGS[0];
  
  pos = 0;
  magic = substr(data, pos, pos + 1); pos += 2;
  
  # check for magic
  if (magic != AG_MAGIC) return 0;
  
  # skip check to 2-byte protocol version
  pos += 2;  
  
  dlen = strlen(data);
  
  # parse commands
  while (pos < dlen)
  {
    cmd  = getbyte(blob:data, pos:pos); pos++;
    
    if (cmd == AG_END_CMD) break;
    
    # get length of parameters
    ret = cint_decode(blob:data, pos:pos);
    if (isnull(ret)) return 0;
    pos += ret['len'];
    params_len = ret['value'];
    
    # read parameters
    if (params_len)
    {
      if (pos + params_len >= dlen) return 0;
      params = substr(data, pos, pos + params_len -1);
      pos += params_len;
    }
  }
  
  # single byte '\x00' follows AG_END_CMD code
  if (pos + 1 == dlen && getbyte(blob:data, pos:pos) == 0) return 1;
  else return 0;
}



port = get_http_port(default:80);


# check for AvantGo web server
# the sync server in M-Business Anywhere uses the 'AvantGo' server string 
srv_hdr = http_server_header(port:port);
if (isnull(srv_hdr)) 
  exit(0, "The banner from the web server on port "+port+" does not have a Server response header.");
if ("AvantGo" >!< srv_hdr)
  exit(0, "The web server on port " +port+ " does not appear to be Sybase M-Business Anywhere (AvantGo) Sync Server.");
  
  
# send a hello command

version = '\x02\x00'; # major and minor

username = rand_str(length:16);
hello_params = cint_encode(strlen(username)) + username + 
              '\x00' +  # 16-byte buffer follows if this compact int is non-zero
              '\x00' +  # 16-byte buffer follows if this compact int is non-zero
              cint_encode(0x3eb3c000) +
              '\x00' +  # this compact int specifies number of bytes that follow
              cint_encode(0x40000001);
              
              
hello_cmd = ag_cmd(cmd: AG_HELLO_CMD, params: hello_params);
end_cmd   = ag_cmd(cmd: AG_END_CMD,   params:NULL);

req = AG_MAGIC + version + hello_cmd + end_cmd;

res = http_send_recv3(method:"POST", port:port, item:"/sync", data:req, content_type:"application/x-mal-client-data", exit_on_fail:TRUE);

if (
  res[2] &&
  ag_pdu_check(res[2]) && 
  "Invalid login.  Please check your username and password and try again." >< res[2]
)
{
  register_service(port:port, proto:"AvantGo-sync-server");
  security_note(port);
}
else exit(1, 'The web server on port ' + port + ' returned an unexpected response:\n' + hexdump(ddata:res[2]));


      


  
