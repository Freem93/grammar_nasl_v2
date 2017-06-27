#TRUSTED 6b4036b40e579e30e9fe8b349b4ae04d30acf310350c348be5655cdd38f086140158f863cef2a438653811fef0c97e5eaea464453285ba33d97aa772cf8f1299b7f75359a5b19a2236d3ac8bf1836b6125c2ce610d52aae3163d1c912c2d833c78bb9ca27ef7f3d9380964c5fa5dd16ac5d4f6e5bbb7a916b504acbbb859da85afe13df0362b78181b66c0d03f0424b73cb081315361adaa6660a04b495e6a58879a06ff4aece6eeac4439f0f668a04897889f66c5b407f983248cbfb1b9c1a3f08ca9377329e3798dc37760e196030426dca6aeae2cdff745efa76e5a4782af191429d40236df1b74291e25e6b7e8d0ff34546e328a298158e368d74ed393c1a4565dfdb64b8a7d9e6795ec0362c2b946676b94c74a938c30d3cc3c7ceacdaa7d7da673905f454649d5df925eee00c10abd196090f9c5d1d79a68672bc42133046bbf873c58fdcd1844a429bd4dccd7ffeb2b90178095cc183d70c579a20b909ec71acee7a61e50a7886397213dbd9d2e9d55d415aa6b5c4cad07e58e2dacc7fae9334bbcdc5a728cca3ebddedb01f313d865ad757b1a2b5f28c5b32ba137718663cc743717fdb75bb060cce6d3d510ce3577c559a8ca6fb25609919fc60f239b7905c7127c769d1ffcb900860d200f922fec2b3cf6dfecf97d2921e0c1e95ac802b9c955fdecc3de5a09c9c0eb002335858a45fb0cc6b4ad742eb6ee29775a
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# string.inc
#
# Revision: 1.4
#

include("string_pack.inc");
include("string_printf.inc");

##
# Check whether an object is a string.
#
# Basically, a wrapper around typeof().
#
# @anonparam obj Object to be examined.
#
# @return TRUE if the object is of type 'data' or 'string'.
##
function is_string()
{
  local_var type;

  type = typeof(_FCT_ANON_ARGS[0]);

  return (type == "data" || type == "string");
}

##
# Return a number of characters from the start of a string.
#
# Basically, a wrapper around substr() that makes life much easier.
#
# @anonparam s The string.
# @anonparam n The number of characters.
#
# @return The first n bytes from string s.
##
function left()
{
  local_var n, s;

  if (max_index(_FCT_ANON_ARGS) != 2)
    return "";

  s = _FCT_ANON_ARGS[0];
  n = _FCT_ANON_ARGS[1];

  if (!is_string(s) || s == "" || n <= 0)
    return "";

  if (n >= strlen(s))
    return s;

  return substr(s, 0, n - 1);
}

##
# Return a number of characters from the end of a string.
#
# @anonparam s The string.
# @anonparam n The number of characters.
#
# @return The last n bytes from string s.
##
function right()
{
  local_var l, n, s;

  if (max_index(_FCT_ANON_ARGS) != 2)
    return "";

  s = _FCT_ANON_ARGS[0];
  n = _FCT_ANON_ARGS[1];

  if (!is_string(s) || s == "" || n <= 0)
    return "";

  l = strlen(s);
  if (n >= l)
    return s;

  return substr(s, l - n, l - 1);
}

##
# Reverse a string.
#
# @anonarg s The string to reverse.
#
# @return The string, reversed.
##
function string_reverse()
{
  local_var i, r, s;

  if (max_index(_FCT_ANON_ARGS) != 1)
    return "";

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s) || s == "")
    return "";

  r = "";
  for (i = strlen(s) - 1; i >= 0; i--)
    r += s[i];

  return r;
}

##
# Convert input -- a string or a number -- to a digit.
#
# @anonparam n Input to convert.
#
# @param base Optional base to use. Default: 16.
# @param ucase If TRUE, return an uppercase digit.
#
# @return A single digit betweeen '0' and 'z', '0' on error.
##
function to_digit(base, ucase)
{
  local_var mask, off, s;

  if (max_index(_FCT_ANON_ARGS) != 1)
    return "0";

  s = _FCT_ANON_ARGS[0];
  if (isnull(s) || s == "")
    return "0";
  s = int(s);

  if (isnull(base))
    base = 16;

  if (base < 2 || base > 36)
    return "0";

  s %= base;

  if (s < 10)
    return string(s);

  if (ucase)
    off = "A";
  else
    off = "a";

  return raw_string(ord(off) + s - 10);
}

##
# Convert a single hexatridecimal / sexatrigesimal digit into decimal.
#
# Typically, the input is '0' - '9' and 'a' - 'f', but values between
# 'g' and 'z' are also accepted (as the values 16 - 35).
#
# @anonparam n The nibble, as a string.
#
# @return An integer betweeen 0 and 35, 0 on error.
##
function from_digit()
{
  local_var n, s;

  if (max_index(_FCT_ANON_ARGS) != 1)
    return 0;

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s) || s == "" || strlen(s) > 1)
    return 0;

  n = ord(tolower(s[0]));

  if (n >= ord("0") && n <= ord("9"))
    return n - ord("0");

  if (n >= ord("a") && n <= ord("z"))
    return n - ord("a") + 10;

  return 0;
}

##
# Convert a string representation of a number of the given base into the
# integer representation. The number can be any size, but NASL only currently
# supports 32-bit integers.
#
# The most common bases are binary (2), octal (8), decimal (10), and
# hexadecimal (16). Any base up to 36 can be used, though, with a - z
# representing 10 - 35.
#
# @remark No handling of overflows is performed.
#
# @remark No handling of digits incompatible with the base is performed.
#
# @anonparam s String to be converted.
#
# @param base Optional base, 10 by default.
#
# @return An unsigned integer representing the value, 0 on error.
##
function strtol(base)
{
  local_var s, i, place, result;

  if (max_index(_FCT_ANON_ARGS) != 1)
    return 0;

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s) || s == "")
    return 0;

  if (isnull(base))
    base = 10;

  if (base < 2 || base > 36)
    return 0;

  place = 1;
  result = uint(0);
  for (i = strlen(s) - 1; i >= 0; i--)
  {
    result += from_digit(s[i]) * place;
    place *= base;
  }

  return result;
}

##
# Given an integer value, convert it to the corresponding string in the
# given base (default base 10).
#
# The most common bases are binary (2), octal (8), decimal (10), and
# hexadecimal (16). Any base up to 36 can be used, though, with a - z
# representing 10 - 35.
#
# This function got extremely complicated with edgecases, since the goal was
# to support everything that the printf suite of functions can do. In the end,
# it does, but has quite a few rare codepaths. Fortunately, all arguments
# are optional, so you don't need to use most of them for most cases.
#
# @remark Due to technical limitations, this overflows after 7 hex digits.
#
# @anonparam i           Integer to convert.
#
# @param base            Optional base. Default 10.
# @param leading_plus    Add a plus sign in front of positive numbers.
# @param leading_space   Add a space in front of positive numbers.
# @param left_justify    If set along with the width argument, will pad on the right instead of the left.
# @param lsb_first       The most significant bit/nibble/extra is first, rather than last. Default: FALSE.
# @param precision       If set, it pads the string to at least that size using either zeroes or the appropriate sign bit.
# @param prepend         If set, prepend this value to the string (eg, "0x") before padding.
# @param twos_complement If set, take the two's complement of negative values rather than simply prepending a minus sign. Only works for base 2, 8, and 16.
# @param width           The total width of the field (will pad with spaces).
# @param ucase           If set, return an uppercase digit.
#
# @return A string representing the value.
##
function ltostr(base, leading_plus, leading_space, left_justify, lsb_first, precision, prepend, twos_complement, width, ucase)
{
  local_var b, i, is_negative, j, s, m, type;

  i = _FCT_ANON_ARGS[0];
  if (isnull(i))
    return "";

  type = typeof(i);
  if (type != "int" && type != "uint")
    return "";

  # Set the default precision to zero.
  if (isnull(precision))
    precision = 0;

  # Set the default base to decimal.
  if (isnull(base))
    base = 10;

  if (base < 2 || base > 36)
    return "";

  # Handle two's complement -1 special. As the only value where
  # (~value - 1) is negative, it requires special treatment.
  s = "";
  if (twos_complement == TRUE && i == -1)
  {
    is_negative = TRUE;

    if (base == 2)
      s = "1";
    else if (base == 8)
      s = "";
    else if (base == 16)
      s = "";
    else
      # This is undefined for other bases.
      return "";
  }
  else
  {
    # Handle negative values
    if (i < 0)
    {
      is_negative = TRUE;
      if (twos_complement)
      {
        # Loop through all the bits from the left to the right, clearing them.
        # When we either get to the far right, or reach a 0 bit, we stop.
        for (j = 31; j >= 0 && ((i & 1 << j) != 0); j--)
          i = i & ~(1 << j);

        # Now, we have a string that starts with a 0. Because it's a
        # negative number, we now have to add the sign bit(s) back to
        # the number.
        if (base == 2)
        {
          # In binary, we simply set the left-most bit.
          i = i | (1 << ++j);
        }
        else if (base == 8)
        {
          # In octal, we set '1' bits until we reach a multiple of 3
          # bits (the length of a digit in octal).
          while (++j % 3 != 0)
            i = i | (1 << j);
        }
        else if (base == 16)
        {
          # In hexadecimal, we set '1' bits until we reach a multiple
          # of 4 bits (the length of a digit in hex).
          while (++j % 4 != 0)
            i = i | (1 << j);
        }
      }
      else
      {
        # If we aren't doing two's complement, just invert the number
        # (we add the minus sign later)
        i *= -1;
      }
    }

    # At this point, 'i' is a positive number that we can convert into
    # the proper base. We worry about adding the sign and stuff back
    # later. Now we use a standard algorithm to convert the number to
    # the appropriate base.
    s = "";
    for (j = 31; j >= 0; j--)
    {
      # Calculate the multiplier, and check for an overflow and skip
      # over it.
      m = base ** j;
      if (m == 0)
        continue;

      # Extract the next bit.
      b = i / m;

      # Remove that bit from the integer.
      i %= m;

      # If the bit is '0' and the string is blank, don't add it.
      if (b == 0 && s == "")
        continue;

      b = to_digit(b, base:base, ucase:ucase);
      if (lsb_first)
        s = b + s;
      else
        s = s + b;
    }

    # If the string was blank, consider it to mean zero.
    if (s == "")
      s = "0";
  }

  # Format negative values properly.
  if (is_negative)
  {
    # If it's two's complement, pad it with sign bits.
    if (twos_complement)
    {
      if (base == 2)
      {
        # Pad with '1's, as needed.
        s = lpad(s, precision, char:"1");
      }
      else if (base == 8)
      {
        # Pad with at least one '7', then more if needed.
        s = "7" + s;
        s = lpad(s, precision, char:'7');
      }
      else if (base == 16)
      {
        # Pad with at least one 'f', then more if needed.
        s = "f" + s;
        s = lpad(s, precision, char:"f");
      }
      else
      {
        # This is undefined for other bases.
        return "";
      }

      # If no precision is given, prepend '..', which represents an
      # infinite number of the first character.
      if (!precision)
        s = ".." + s;
    }
    else
    {
      # If it's negative and not two's complement, prepend a minus
      # sign (it's already an absolute value)
      s = "-" + lpad(s, precision, char:"0");
    }
  }
  else
  {
    # For positive values, lower the precision if we're added a plus
    # or a space
    if (width == 0)
    {
      if (leading_plus)
        precision--;
      if (leading_space)
        precision--;
    }

    # If we're prepending something (e.g., '0x', '0b', or '0'), remove
    # that much from the precision
    if (!isnull(prepend))
      precision -= strlen(prepend);

    if (lsb_first)
      s = rpad(s, precision, char:"0");
    else
      s = lpad(s, precision, char:"0");

    if (leading_plus)
      s = "+" + s;
    if (leading_space)
      s = " " + s;
  }

  # Prepend the appropriate data, if necessary.
  if (!isnull(prepend))
    s = prepend + s;

  # Pad the data to the requested width, if necessary.
  if (!isnull(width))
  {
    if (left_justify)
      s = rpad(s, width);
    else
      s = lpad(s, width);
  }

  return s;
}

##
# Convert a byte - between 0 and 255 - into the corresponding hex
# representation.
#
# @anonparam b The byte to convert.
# @param ucase If set to TRUE, return the hex in uppercase.
# @param lsn_first If set to TRUE, put the least significant nibble first.
#
# @return A 2-character hex string.
##
function byte_to_hex(ucase, lsn_first)
{
  local_var b, n1, n2;

  b = int(_FCT_ANON_ARGS[0]);

  # Grab the first two nibbles
  n1 = to_digit((b & 0xF0) >> 4, ucase:ucase);
  n2 = to_digit((b & 0x0F) >> 0, ucase:ucase);

  if (lsn_first)
    return n2 + n1;

  return n1 + n2;
}

##
# Pads a string on the left side to the given length.
#
# @anonparam s The string to pad.
# @anonparam length The desired length.
#
# @param char The character for padding; optional. Default: space.
#
# @return The string padded to the proper length.
##
function lpad(char)
{
  local_var len, pad, s;

  if (max_index(_FCT_ANON_ARGS) != 2)
    return "";

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s))
    return "";

  len = int(_FCT_ANON_ARGS[1]);
  if (len <= 0 || strlen(s) >= len)
    return s;

  if (isnull(char))
    char = " ";

  return crap(data:char, length:len - strlen(s)) + s;
}

##
# Pads a string on the right side to the given length.
#
# @anonparam s The string to pad.
# @anonparam length The desired length.
#
# @param char The character for padding; optional. Default: space.
#
# @return The string padded to the proper length.
##
function rpad(char)
{
  local_var len, pad, s;

  if (max_index(_FCT_ANON_ARGS) != 2)
    return "";

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s))
    return "";

  len = int(_FCT_ANON_ARGS[1]);
  if (len <= 0 || strlen(s) >= len)
    return s;

  if (isnull(char))
    char = " ";

  return s + crap(data:char, length:len - strlen(s));
}

##
# Masks a string with '*' char.
#
# @param  string string      String to mask.
# @param  int    mask_length OPTIONAL length of masking. If 0, then
#                            len(input) = len(output). Defaults to 6.
#
# @return string masked, NULL on error.
##
function mask_string(string, mask_length)
{
  # Accept string anonymously.
  if (isnull(string)) string = _FCT_ANON_ARGS[0];
  if (isnull(string))
  {
    err_print("mask_string(): missing required arg 'string'");
    return NULL;
  }

  if (isnull(mask_length)) mask_length = 6;
  else if (mask_length == 0) mask_length = len(string) - 2;
  else if (mask_length < 0)
  {
    err_print("mask_string(): arg mask_length must be nonnegative");
    return NULL;
  }

  return strcat(string[0], crap(data:'*', length:mask_length), string[len(string) - 1]);
}
