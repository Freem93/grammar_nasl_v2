###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# adobe_flash_func.inc
# $Revision: 1.2 $
#
# @include misc_func.inc
# @include http.inc
###

##
# Error codes
##
SWF_OK                  = 0;
SWF_MISSING_PORT        = 1;
SWF_MISSING_ITEM        = 2;
SWF_NULL_RESPONSE       = 3;
SWF_NOT_TYPE_CWS        = 4;
SWF_DECOMPRESSION_ERROR = 5;

##
# Requests an SWF file from a web server
#
# @param port port to send request to
# @param item item to request, e.g. /SE/EMC_SE.swf
# @param exit_on_fail TRUE or FALSE to be passed through to http_send_recv3
#
# @return an array consisting of an ['error'] key with an error code value
#         and, if the error code is SWF_OK, a ['data'] key containing the
#         SWF file
##
function get_swf(port, item, exit_on_fail)
{
  local_var length, res;

  if (empty_or_null(port))
    audit(AUDIT_FN_FAIL, 'get_swf', 'Missing port argument');
  if (empty_or_null(item))
    return make_array('error', SWF_MISSING_ITEM);
  if(isnull(exit_on_fail))
    exit_on_fail = TRUE;

  # The Flash file is likely larger than our default _http_max_req_sz: 1048576
  # Grab headers first, then set the max size to the size we need before
  # requesting the file itself

  res = http_send_recv3(
    method:'GET',
    port:port,
    item:item,
    no_body:TRUE,
    exit_on_fail:exit_on_fail
  );

  if (isnull(res))
    return make_array('error', SWF_NULL_RESPONSE);

  length = eregmatch(pattern:'(^|\r\n)Content-length:[ \t  ]*([0-9]+)', string:res[1], icase:TRUE);

  if (!empty_or_null(length))
  {
      length = int(length[2]);
      if (length > 0)
        http_set_max_req_sz(length);
  }

  res = http_send_recv3(
    method:'GET',
    port:port,
    item:item,
    exit_on_fail:exit_on_fail
  );

  if (isnull(res))
    return make_array('error', SWF_NULL_RESPONSE);

  return make_array('error', SWF_OK, 'data', res[2]);
}

##
# Checks an SWF file to see if it is compressed (file type CWS)
#
# @anonparam SWF file to check
#
# @return TRUE if the SWF file is compressed file type CWS, FALSE otherwise
##
function is_swf_cws_compressed()
{
  local_var type;

  data = _FCT_ANON_ARGS[0];
  type = substr(data, 0, 3);
  if (type == '\x43\x57\x53\x09')
    return TRUE;
  else
    return FALSE;
}

##
# Decompresses a compressed SWF file (type CWS)
#
# @anonparam SWF file to decompress
#
# @return an array consisting of an ['error'] key with an error code value
#         and, if the error code is SWF_OK, a ['data'] key containing the
#         decompressed SWF file
##
function decompress_swf()
{
  local_var stream;

  data = _FCT_ANON_ARGS[0];

  if(!is_swf_cws_compressed(data))
    return make_array('error', SWF_NOT_TYPE_CWS);

  data = substr(data,8);

  stream = gzip_inflate_init(windowBits:15);
  data   = gzip_inflate(data:data, stream:stream);
  gzip_inflate_end(stream);

  if(empty_or_null(data))
    return make_array('error', SWF_DECOMPRESSION_ERROR);

  return make_array('error', SWF_OK, 'data', data);
}

##
# Accepts an error code and returns a string describing the error condition
#
# @anonparam error code
#
# @return NULL if the error code is SWF_OK, otherwise a string describing
#         the error condition
##
function swf_error_msg()
{
  local_var error;
  error = _FCT_ANON_ARGS[0];

  if (error == SWF_OK)
    return NULL;
  else if (error == SWF_MISSING_PORT)
    return "Missing 'port' argument.";
  else if (error == SWF_MISSING_ITEM)
    return "Missing 'item' argument.";
  else if (error == SWF_NULL_RESPONSE)
    return "The remote web server failed to respond to the request.";
  else if (error == SWF_NOT_TYPE_CWS)
    return "The data type is not CWS (compressed SWF).";
  else if (error == SWF_DECOMPRESSION_ERROR)
    return "Failure decompressing the SWF file.";
}
