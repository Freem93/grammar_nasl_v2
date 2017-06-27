#TRUSTED 194059b571ad5bd04cbb05054f2957a6647c2387e7259a33352e052148998477bfa4440743c9643e249523ecdbbc2a9d972dde9523dba18efd24296552eb902a50391789327cb47a8ee9bf69122ba9c77ecc377c38e0e32311f9b7ecba5d1313e922b7d059615e0a69117cdcbe5bc58f2732b6eb9dc2f9320d1b5c4d5e24cfffb3b5e6479e78e25680bf6c8bee6208b676dbf3d69f7a6588b98a19974fb60f83727be9f01976311e83879ce1a4dcbbc780290ba06ac5d9e8a8a5842b9c64f721a2e749130df35a696886afbd4965e969bcf42969cbb007806b9bc85dd8fa4c216632f1c9bf1058ebcb0ee1b65669c47de46ff25a61e81fd76906043468446d59ab8aadcb8f298071e0735f15f9970773623c8c113fd604528e08fec5fb63d9d2b7c09a78a19231f61d6189aef59b35c56637440f74cf2984f86987815f3ec752fe1c499b41071a9a8322a413a09a71846cc22a45ef289287ce95c9506db084d42eba7581feb041545829fa1ad26a5ad1bd11e241ecf590539a24398a6cfe77bff51fe56ffa04d05e04d2864ccd12812b9ae1de635f6971dcc80302d929b6731e2f89d9bfff4af2ff04f65d66f1efed22e9499035ca543165a426f157ed0c2ce254145e14e1c6d07bda1f6be845996c5d341c056b12a8a48078f52550155e458ac7b7a52c3258d002c998b87a437080688b0b75c804e178663aab4713028f5d9a
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# byte_func.inc
#
# Revision: 1.10
##

######################################################################
# Byte Order Functions
######################################################################

global_var BYTE_ORDER_BIG_ENDIAN, BYTE_ORDER_LITTLE_ENDIAN;
BYTE_ORDER_BIG_ENDIAN = 1;
BYTE_ORDER_LITTLE_ENDIAN = 2;

global_var __byte_order_index, __byte_order_stack;
__byte_order_index = 0;
__byte_order_stack = make_list(BYTE_ORDER_BIG_ENDIAN);

function get_byte_order()
{
  return __byte_order_stack[__byte_order_index];
}

function pop_byte_order()
{
  # Never pop our default byte order.
  if (__byte_order_index == 0)
    return;

  __byte_order_stack[__byte_order_index--] = NULL;
}

function push_byte_order()
{
  __byte_order_stack[++__byte_order_index] = _FCT_ANON_ARGS[0];
}

function set_byte_order()
{
  # Overwrite all byte order settings.
  __byte_order_index = 0;
  __byte_order_stack = make_list(_FCT_ANON_ARGS[0]);
}

######################################################################
# Byte Emission Functions
######################################################################

function mkpad()
{
  local_var l;

  l = _FCT_ANON_ARGS[0];
  if (isnull(l))
    l = 0;

  return crap(data:'\0', length:l);
}

function mkbyte()
{
  return raw_string(0xFF & _FCT_ANON_ARGS[0]);
}

function mkword(order)
{
  local_var l;

  l = _FCT_ANON_ARGS[0];


  if (isnull(order))
    order = get_byte_order();

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return raw_string((l >> 8) & 0xFF, l & 0xFF);
  else
    return raw_string(l & 0xFF, (l >> 8) & 0xFF);
}

function mkdword(order)
{
  local_var l;

  if (isnull(order))
    order = get_byte_order();

  l = _FCT_ANON_ARGS[0];

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return raw_string(
      (l >> 24) & 0xFF,
      (l >> 16) & 0xFF,
      (l >>  8) & 0xFF,
      l & 0xFF
    );
  else
    return raw_string(
      l & 0xFF,
      (l >>  8) & 0xFF,
      (l >> 16) & 0xFF,
      (l >> 24) & 0xFF
    );
}

######################################################################
# Byte Parsing Functions
######################################################################

function getbyte(blob, pos)
{
  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(pos))
    pos = 0;

  if (pos < 0)
    return NULL;

  if (pos + 1 > strlen(blob))
    return NULL;

  return ord(blob[pos]);
}

function getword(blob, order, pos)
{
  local_var s;

  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(order))
    order = get_byte_order();

  if (isnull(pos))
    pos = 0;

  if (pos < 0)
    return NULL;

  if (pos + 2 > strlen(blob))
    return NULL;

  s = substr(blob, pos, pos + 1);

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return ord(s[0]) << 8 | ord(s[1]);
  else
    return ord(s[0]) | ord(s[1]) << 8;
}

function getdword(blob, order, pos)
{
  local_var l, s;

  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(order))
    order = get_byte_order();

  if (isnull(pos))
    pos = 0;

  if (pos < 0)
    return NULL;

  if (pos + 4 > strlen(blob))
    return NULL;

  s = substr(blob, pos, pos + 3);

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return
      ord(s[0]) << 24 |
      ord(s[1]) << 16 |
      ord(s[2]) <<  8 |
      ord(s[3]);
  else
    return
      ord(s[0]) |
      ord(s[1]) <<  8 |
      ord(s[2]) << 16 |
      ord(s[3]) << 24;
}

function getqword_shift(blob, order, pos, shift)
{
  local_var end, i, shift1, shift8, start, xx, yy;

  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(order))
    order = get_byte_order();

  if (isnull(pos))
    pos = 0;

  if (isnull(shift))
    shift = 0;

  if (pos < 0)
    return NULL;

  if (pos + 8 > strlen(blob))
    return NULL;

  if (shift < 0)
    return NULL;

  if (shift >= 64)
    return NULL;

  shift8 = shift / 8;
  shift1 = shift - 8 * shift8;

  yy = 0;
  xx = 0;

  if (order == BYTE_ORDER_BIG_ENDIAN)
  {
    start = 4 - shift8;
    if (start < 0)
      start = 0;

    for (i = start; i <= 7 - shift8; i++)
      xx = (xx << 8) | ord(blob[pos + i]);

    if (shift < 32)
      yy = ord(blob[pos + 3 - shift8]);
  }
  else
  {
    end = shift8 + 3;
    if (end > 7)
      end = 7;

    for (i = end; i >= shift8; i--)
      xx = (xx << 8) | ord(blob[pos + i]);

    if (shift < 32)
      yy = ord(blob[pos + shift8 + 4]);
  }

  if (shift1 > 0)
    yy <<= (8 - shift1) + 24;
  else
    yy = 0;

  xx >>>= shift1;

  return (xx | yy);
}

##
# Extracts printable strings from a buffer.
#
# @param  data   buf        Buffer of data to extract strings from.
# @param  int    len        OPTIONAL Length of buffer to search,
#                           defaults to 1024.
# @param  int    min_len    OPTIONAL Minimum length of printable chars
#                           to be considered a string, defaults to 4.
# @param  bool   null_term  OPTIONAL whether or not a string must be
#                           NULL terminated to be considered a string,
#                           defaults to FALSE.
#
# @return list  of strings
##
function get_strings(buf, len, min_len, null_term)
{
  local_var offset, char, string;
  local_var strings;

  strings = make_list();
  string = '';

  if (isnull(buf)) buf = _FCT_ANON_ARGS[0];
  if (isnull(buf))
  {
    err_print("get_strings(): missing required arg 'buf");
    return strings;
  }

  # Set default values.
  if (isnull(len)) len = 1024;
  if (isnull(min_len)) min_len = 4;
  if (isnull(null_term)) null_term = FALSE;

  # Ensure we don't read past the end of the buffer.
  if (len(buf) < len) len = len(buf);

  # Iterate through the buffer up to the max length.
  for (offset = 0; offset < len; offset++)
  {
    # If the current byte is printable add it to the current string.
    # Otherwise if the current byte is the NULL terminator and the
    # string is above the minimum length, add the string to the list
    # of strings.
    char = getbyte(blob:buf, pos:offset);
    if (is_ascii_printable(raw_string(char))) string += raw_string(char);
    else
    {
      if ((!null_term || char == 0) && len(string) >= min_len) strings = make_list(strings, string);
      string = '';
    }
  }

  # Check if we have a valid string at the end of our buffer.
  if (len(string) >= min_len) strings = make_list(strings, string);

  return strings;
}
