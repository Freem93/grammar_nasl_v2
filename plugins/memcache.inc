#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# $Revision: 1.1 $
#

#
# requires byte_func.inc
#
# memcache binary protocol spec at http://code.google.com/p/memcached/wiki/BinaryProtocolRevamped
#

MEMCACHE_HDR_LEN  = 0x18;

# Packet types
MEMCACHE_REQ      = 0x80;
MEMCACHE_RESP     = 0x81;

# Response codes 
MEMCACHE_RESP_NO_ERROR            = 0x0000;
MEMCACHE_RESP_KEY_NOT_FOUND       = 0x0001;
MEMCACHE_RESP_KEY_EXISTS          = 0x0002;
MEMCACHE_RESP_VALUE_TOO_BIG       = 0x0003;
MEMCACHE_RESP_BAD_ARGS            = 0x0004;
MEMCACHE_RESP_NOT_STORED          = 0x0005;
MEMCACHE_RESP_BAD_INCDEC          = 0x0006;
MEMCACHE_RESP_BAD_VBUCKET         = 0x0007;
MEMCACHE_RESP_AUTH_ERR            = 0x0020;
MEMCACHE_RESP_AUTH_CONTINUE       = 0x0021;
MEMCACHE_RESP_UNK_CMD             = 0x0081;
MEMCACHE_RESP_NO_MEM              = 0x0082;
MEMCACHE_RESP_NOT_SUPPORTED       = 0x0083;
MEMCACHE_RESP_INTERNAL_ERR        = 0x0084;
MEMCACHE_RESP_BUSY                = 0x0085;
MEMCACHE_RESP_TMP_FAILURE         = 0x0086;

# Command opcodes
MEMCACHE_CMD_GET                  = 0x00;
MEMCACHE_CMD_SET                  = 0x01;
MEMCACHE_CMD_ADD                  = 0x02;
MEMCACHE_CMD_REPLACE              = 0x03;
MEMCACHE_CMD_DELETE               = 0x04;
MEMCACHE_CMD_INC                  = 0x05;
MEMCACHE_CMD_DEC                  = 0x06;
MEMCACHE_CMD_QUIT                 = 0x07;
MEMCACHE_CMD_FLUSH                = 0x08;
MEMCACHE_CMD_GETQ                 = 0x09;
MEMCACHE_CMD_NOP                  = 0x0a;
MEMCACHE_CMD_VERSION              = 0x0b;
MEMCACHE_CMD_GETK                 = 0x0c;
MEMCACHE_CMD_GETKQ                = 0x0d;
MEMCACHE_CMD_APPEND               = 0x0e;
MEMCACHE_CMD_PREPEND              = 0x0f;
MEMCACHE_CMD_STAT                 = 0x10;
MEMCACHE_CMD_SETQ                 = 0x11;
MEMCACHE_CMD_ADDQ                 = 0x12;
MEMCACHE_CMD_REPLACEQ             = 0x13;
MEMCACHE_CMD_DELETEQ              = 0x14;
MEMCACHE_CMD_INCQ                 = 0x15;
MEMCACHE_CMD_DECQ                 = 0x16;
MEMCACHE_CMD_QUITQ                = 0x17;
MEMCACHE_CMD_FLUSHQ               = 0x18;
MEMCACHE_CMD_APPENDQ              = 0x19;
MEMCACHE_CMD_PREPENDQ             = 0x1a;
MEMCACHE_CMD_VERBOSITY            = 0x1b;
MEMCACHE_CMD_TOUCH                = 0x1c;
MEMCACHE_CMD_GAT                  = 0x1d;
MEMCACHE_CMD_GATQ                 = 0x1e;
MEMCACHE_CMD_SASL_MECH            = 0x20;
MEMCACHE_CMD_SASL_AUTH            = 0x21;
MEMCACHE_CMD_SASL_STEP            = 0x22;
MEMCACHE_CMD_RGET                 = 0x30;
MEMCACHE_CMD_RSET                 = 0x31;
MEMCACHE_CMD_RSETQ                = 0x32;
MEMCACHE_CMD_RAPPEND              = 0x33;
MEMCACHE_CMD_RAPPENDQ             = 0x34;
MEMCACHE_CMD_RPREPEND             = 0x35;
MEMCACHE_CMD_RPREPENDQ            = 0x36;
MEMCACHE_CMD_RDELETE              = 0x37;
MEMCACHE_CMD_RDELETEQ             = 0x38;
MEMCACHE_CMD_RINC                 = 0x39;
MEMCACHE_CMD_RINCQ                = 0x3a;
MEMCACHE_CMD_RDEC                 = 0x3b;
MEMCACHE_CMD_RDECQ                = 0x3c;
MEMCACHE_CMD_SET_VBUCKET          = 0x3d;
MEMCACHE_CMD_GET_VBUCKET          = 0x3f;
MEMCACHE_CMD_TAP_CONNECT          = 0x40;
MEMCACHE_CMD_TAP_MUTATION         = 0x41;
MEMCACHE_CMD_TAP_DELETE           = 0x42;
MEMCACHE_CMD_TAP_FLUSH            = 0x43;
MEMCACHE_CMD_TAP_OPAQUE           = 0x44;
MEMCACHE_CMD_TAP_VBUCKET_SET      = 0x45;
MEMCACHE_CMD_TAP_VBUCKET_START    = 0x46;
MEMCACHE_CMD_TAP_VBUCKET_END      = 0x47;


##
# Creates a memcache request packet header
#
# @param cmd command opcode
# @param key_len length of data key
# @param extra_len length of extra data for the command
# @param body_len total body length of the request packet
# @param datatype 'data type' field of the memcache packet
# @param vbucket_id 'vbucket id' field of the memcache request packet
# @param opaque 'opaque' field of the memcache packet
# @param cas 'cas' field of the memcache packet
# @return formatted memcache request packet header
##
function mcb_mk_req_hdr(cmd, key_len, extra_len, body_len, datatype, vbucket_id, opaque, cas)
{
  local_var hdr;

  hdr = mkbyte(MEMCACHE_REQ) +
        mkbyte(cmd) +
        mkword(key_len) +
        mkbyte(extra_len) +
        mkbyte(datatype) +
        mkword(vbucket_id) +
        mkdword(body_len) +
        opaque +
        cas;

  return hdr;
}

##
# Creates a memcache request packet
#
# @param cmd command opcode
# @param key data key
# @param value data value
# @param extra extra data for the command
# @param datatype 'data type' field of the memcache packet
# @param vbucket_id 'vbucket id' field of the memcache request packet
# @param opaque 'opaque' field of the memcache packet
# @param cas 'cas' field of the memcache packet
# @return formatted memcache request packet
# @remark 
#   - Return NULL if 'cmd' is not specfied
#   - All other fields can be NULL
#   - Non-specified fields in the header are assigned a default value
##
function mcb_mk_req(cmd, key, value, extra, datatype, vbucket_id, opaque, cas)
{
  local_var blen, elen, hdr, klen, req;

  if(isnull(cmd)) return NULL;

  # Set defaults
  if(isnull(datatype))    datatype   = 0x00;
  if(isnull(vbucket_id))  vbucket_id = 0x0000;
  if(isnull(opaque))      opaque = raw_string(0x00, 0x00, 0x00, 0x00);
  if(isnull(cas))         cas = raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
 

  klen = strlen(key);
  elen = strlen(extra);
  blen = elen + klen + strlen(value);

  hdr = mcb_mk_req_hdr(cmd: cmd, 
                      key_len: klen,  
                      extra_len: elen, 
                      body_len: blen, 
                      datatype: datatype,
                      vbucket_id: vbucket_id,
                      opaque: opaque, 
                      cas:cas);


  req = hdr + extra + key + value;

  return req;
}

##
# Parses a memcache response
#
# @anonparam memcache response packet
# @return ret['status'] - response status code
#         ret['cmd'] - command opcode
#         ret['key'] - data key if any
#         ret['value'] - data value if any
#         ret['extra'] - command-specific extra data if any
#         ret['datatype'] - 'data type' field of the memcache packet
#         ret['opaque'] - 'opaque' field of the memcache packet
#         ret['cas'] - 'cas' field of the memcache packet
# @remark
#   - return NULL on parsing error
##
function mcb_parse_resp()
{
  local_var blen, data, dlen, elen, klen, pos, ret;

  data = _FCT_ANON_ARGS[0];

  dlen = strlen(data);

  # Check for mininum len 
  if(dlen < MEMCACHE_HDR_LEN) return NULL;
  
  # Make sure it's a response packet 
  if(getbyte(blob:data, pos: 0) != MEMCACHE_RESP)  
    return NULL;

  ret['cmd'] = getbyte(blob:data, pos: 1);

  # Get key len
  klen = getword(blob:data, pos: 2);

  # Get len for the extra field
  elen = getbyte(blob:data, pos: 4);

  ret['datatype'] = getbyte(blob:data, pos: 5);
  ret['status']   = getword(blob:data, pos: 6);
  
  # Get total body len  
  blen = getdword(blob:data, pos: 8);

  # Length checks
  if( MEMCACHE_HDR_LEN + blen != dlen) return NULL;
  if(elen + klen > blen)return NULL;

  ret['opaque'] = substr(data, 12, 15);
  ret['cas']    = substr(data, 16, 23);
    
  # Get body contents
  pos = 24;

  # Content of the extra field
  if(elen)
  {
    ret['extra'] = substr(data, pos, pos + elen -1);
    pos += elen;
  }

  # Key
  if(klen)
  {
    ret['key'] = substr(data, pos, pos + klen -1);
    pos += klen;
  }

  # Value
  if( pos < dlen)
  {
    ret['value'] = substr(data, pos);  
  }

  return ret; 

}

##
# Reads memcache packet from a socket
#
# @param socket socket to a connected memcached server
# @return a memcache response 
##
function mcb_read_resp(socket)
{
  local_var blen, body, hdr;

  # Get pkt header
  hdr = recv(socket: socket, length: MEMCACHE_HDR_LEN, min: MEMCACHE_HDR_LEN);
  if(isnull(hdr)) return NULL;

  # Get total body length
  blen = getdword(blob: hdr, pos: 8);

  # No body content
  if(blen == 0) return hdr;
 
  # Sanity check for body len
  if(blen > 1024 * 1024)
    return NULL; 
 
  body = recv(socket: socket, length: blen, min: blen);
  if(isnull(body)) return NULL;

  return (hdr + body);

}
