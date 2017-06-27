# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# stream_func.inc
#
# $Revision: 1.1 $

include ("byte_func.inc");

global_var __stream, __stream_pos;

__stream = NULL;
__stream_pos = 0;


#---------------------------------------------------------#
# Function    : stream_init                               #
# Description : Initializes a new stream                  #
# Return      : stream handle                             #
#---------------------------------------------------------#

function stream_init()
{
 local_var data, stream, s;
 data = _FCT_ANON_ARGS[0];

 s = __stream_pos++;

 stream[0] = data;           # data
 stream[1] = 0;              # pos
 stream[2] = strlen(data);   # len
 stream[3] = 0;              # error

 __stream[s] = stream;
 return s;
}


#---------------------------------------------------------#
# Function    : stream_end                                #
# Description : Frees stream memory                       #
# Return      : No return value                           #
#---------------------------------------------------------#

function stream_end()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 __stream[s] = NULL;
}


function stream_is_end()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return (__stream[s][1] >= __stream[s][2]);
}


function stream_get_data()
{
 local_var s, n, tmp;
 s = _FCT_ANON_ARGS[0];
 n = _FCT_ANON_ARGS[1];

 if (n == 0) return NULL;

 tmp = substr(__stream[s][0], __stream[s][1], __stream[s][1]+n-1);
 __stream[s][1] = __stream[s][1] + n;

 return tmp;
}

function stream_get_pos()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return __stream[s][1];
}

function stream_get_length()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return __stream[s][2];
}

function stream_get_dword()
{
 local_var s, buf;
 s = _FCT_ANON_ARGS[0];

 buf = stream_get_data(s, 4);
 return getdword(blob:buf, pos:0);
}

function stream_get_word()
{
 local_var s, buf;
 s = _FCT_ANON_ARGS[0];

 buf = stream_get_data(s, 2);
 return getword(blob:buf, pos:0);
}

function stream_get_byte()
{
 local_var s, b;
 s = _FCT_ANON_ARGS[0];

 b = stream_get_data(s, 1);
 return ord(b);
}

function stream_get_long()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return stream_get_dword(s);
}

function stream_get_ulong()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return stream_get_dword(s);
}

function stream_get_ushort()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return stream_get_word(s);
}

function stream_get_short()
{
 local_var s, v;
 s = _FCT_ANON_ARGS[0];

 v = stream_get_word(s);
 if (v >= 0x8000) v = 0xFFFF0000 | v;

 return v;
}


function stream_get_b_varchar()
{
 local_var len;
 local_var s;
 s = _FCT_ANON_ARGS[0];

 len = stream_get_byte(s) * 2;
 if (len == 0) return NULL;

 return unicode_to_ascii(stream_get_data(s, len));
}

function stream_get_b_varbyte()
{
 local_var len;
 local_var s;
 s = _FCT_ANON_ARGS[0];

 len = stream_get_byte(s);
 if (len == 0) return NULL;

 return stream_get_data(s, len);
}

function stream_get_us_varchar()
{
 local_var len;
 local_var s;
 s = _FCT_ANON_ARGS[0];

 len = stream_get_word(s) * 2;
 if (len == 0) return NULL;

 return unicode_to_ascii(stream_get_data(s, len));
}

function stream_get_length_binary()
{
 local_var s, b;
 s = _FCT_ANON_ARGS[0];

 b = stream_get_byte(s);

 return stream_get_data(s, b);
}

function stream_get_length_string()
{
 local_var s, len, tmp, i;
 s = _FCT_ANON_ARGS[0];

 s = stream_get_length_binary(s);
 len = strlen(s);

 tmp = NULL;
 for (i=0; i<len; i++)
 {
  if (s[i] == '\0') break;

  tmp += s[i];
 }

 return tmp;
}

function stream_get_null_string()
{
 local_var s, b, tmp;
 s = _FCT_ANON_ARGS[0];

 tmp = NULL;

 while(1)
 {
  b = stream_get_data(s, 1);
  if (ord(b) == 0) break;

  tmp += b;
 }

 return tmp;
}

function stream_get_remaining_length()
{
  local_var s;
  s = _FCT_ANON_ARGS[0];

  return stream_get_length(s) - stream_get_pos(s);
}
