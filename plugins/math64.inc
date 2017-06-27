#TRUSTED 33da849618445daa167cb76bae869264193b7401343dd8f59f1a34cb94c4658b157064b1eac9669ac2de75dfaf4c21a75c16b7e5b56609fbbe04573d8d8019f05839ae2179edb611a271d866bc50c0473bc9c3a41844efe8f35ece5f81b7edf1499300e87e47fd937d9cbf6cad9a8c7eb80e9dc9f47b6d6507ce5c9afb244e14335ec1f802c1e342e91d89709e57264110e5ea9a43b226a21b5d62b46bc0ce5a3ed07a5f8fee1bc5476621f1fb4657455a59706a907fd86eaa9b27337539efb99db7a207bf91a6741de824a1f6c1a7767b3bb20a47478b1b50cd409cc55d1824c88b5243d79be8ebcad92b5b3a07804253526035e00b825e4701089d27bf3f67a7021ac2d6413693fdf8963e1acc9365b28c83ede380a90a8ebddf24587f366a7a931fcfe125769de1844fa61194e10268d63e5e05677db5d2c868f6e20df49c9097aae27aaef6005d7ef3b6e3752acca5bc6bed74a2b7345d78e401d2aa7211e152b69c2700e9a8d3ecbcc54c5ce43edfd8056520deea8f16b169816ff88729e27fb298437e66df1959d32d0fd591186292c9988cd2afa5753ce50b1c3f9d61a4cb21c7d40477e5a08dbd7c3ff3f4f97c75d8daff1264a64bad755978e66cada9ad13842a7334249a0a4c5ef4bf2d791d76af6e2685286ffd29f8c189f55c256e5c2ead36063efd4171ea3c0df666a6470103365d144aed02db072321a5fa84
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# These functions peform mathematical operations on 64-bit integers.
# All expected input and output is represented by the return value
# of make_int64().
#
# Example: 0x01030507090B0D0F + 0x0020406080A0C0E0
#
# num1 = make_int64(low:0x090B0D0F, high:0x01030507);
# num2 = make_int64(low:0x80A0C0E0, high:0x00204060);
# res = add64(num1, num2); #returns [0x89ABCDEF, 0x01234567]
###

##
# Creates an int64.  The 64 bit math functions in this library
# only work when provided int64 arguments
#
# @param low low bits
# @param high high bits
# @return an int64
##
function make_int64(low, high)
{
  if (isnull(low)) low = 0;
  if (isnull(high)) high = 0;

  return make_list(low, high);
}

##
# bitwise exclusive or of two int64s
#
# @anonparam a number to XOR
# @anonparam b number to XOR
# @return a ^ b
##
function xor64()
{
  local_var a, b, result;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  result = make_int64(
    low:a[0] ^ b[0],
    high:a[1] ^ b[1]
  );  

  return result;
}

##
# adds two int64s
#
# @anonparam a addend
# @anonparam b addend
# @return a + b
##
function add64()
{
  local_var a, b, carry, sum, i, ai, bi;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];
  sum = make_int64();
  carry = 0;

  if (_unsigned_add_overflows(a[0], b[0]))
  {
    carry = 1;
  }

  sum[0] = a[0] + b[0];
  sum[1] = a[1] + b[1] + carry;

  return sum;
}

function _unsigned_add_overflows()
{
  local_var a, b, sum;

  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if (a < 0 && b < 0)
    return TRUE;

  if ((a < 0 || b < 0) && a + b >= 0)
    return TRUE;

  return FALSE;
}

##
# subtracts two int64s
#
# @param a minuend
# @param b subtrahend
# @return a - b
##
function sub64()
{
  local_var a, b, diff, carry, i, ai, bi;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];
  carry = 0;

  for (i = 0; i < 8; i++)
  {
    ai = (a[i/4] >>> ((i * 8) % 32)) & 0xFF;
    bi = (b[i/4] >>> ((i * 8) % 32)) & 0xFF;
    diff[i/4] += (((ai - bi - carry) & 0xFF)) << ((i * 8) % 32);
    carry = (ai - bi - carry) & 0x100 == 0x100;
  }

  return diff;
}

##
# circular shift to the left on an int64
#
# @anonparam num number to shift
# @return num rotated one bit to the left 
##
function lrot64()
{
  local_var num;
  local_var high, low, carry;

  num = _FCT_ANON_ARGS[0];
  carry = (num[0] & 0x80000000);
  num[1] = (num[1] << 1) | num[0] >> 31;
  num[0] = num[0] << 1;
  if ( carry ) num[0] = num[0] | 1;
  return num;
}

##
# Performs a one's complement on the given int64
#
# @anonparam num number to complement
# @anonparam ~num
##
function compl64()
{
  local_var num;
  num = _FCT_ANON_ARGS[0];

  return make_int64(low:~num[0], high:~num[1]);
}

##
# Performs a logical left bit shift on the given int64
#
# @anonparam num number to shift
# @anonparam bits number of bits to shift left
# @return num << bits
##
function lshift64()
{
  local_var num, bits, mask, carry, low, high;
  num = _FCT_ANON_ARGS[0];
  bits = _FCT_ANON_ARGS[1];

  if(bits < 0 || bits >= 64) return num;

  if(bits < 32)
  {
    mask = (2**bits - 1) << (32 - bits);
    carry = (num[0] & mask) >>> (32 - bits);
    low = num[0] << bits;
    high = (num[1] << bits) | carry;
  }
  else
  {
    low = 0;
    high = num[0] << (bits - 32);
  }
  
  return make_int64(low:low, high:high);
}

##
# Performs a logical right bit shift on the given int64
#
# @anonparam num number to shift
# @anonparam bits number of bits to shift right
# @return num >>> bits
##
function rshift64()
{
  local_var num, bits, mask, carry, low, high;
  num = _FCT_ANON_ARGS[0];
  bits = _FCT_ANON_ARGS[1];

  if(bits < 0 || bits >= 64) return num;

  if(bits < 32)
  {
    mask = 2**bits - 1;
    carry = (num[1] & mask) << (32 - bits);
    low = (num[0] >>> bits) | carry;
    high = num[1] >>> bits;
  }
  else
  {
    low = num[1] >>> (bits - 32);
    high = 0;
  }

  return make_int64(low:low, high:high);
}

##
# Multiplies two int64s
#
# @anonparam a factor
# @anonparam b factor
# @return a * b
##
function mult64()
{
  local_var a, b, ai, bj, i, j, prod, temp;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];
  prod = make_int64();
  
  #for numbers a and b, multiplies ai and bj (where i and j are the ith and
  #jth bytes of a and b respectively), adding partial products along the way.
  for(i = 0; i < 8; i++)
  {
    ai = (a[i/4] >>> ((i * 8) % 32)) & 0xFF;
    temp = make_int64();
 
    for(j = 0; j < 8; j++)
    {
      bj = (b[j/4] >>> ((j * 8) % 32)) & 0xFF;
      temp = add64(temp, lshift64(make_int64(low:ai * bj), j * 8));
    }

    temp = lshift64(temp, i * 8);
    prod = add64(prod, temp);
  }

  return prod;
}

##
# Performs the modulus operation on two int64s
#
# @anonparam n numerator
# @anonparam d denominator
# @return n % d
##
function mod64()
{
  local_var n, d, result;
  n = _FCT_ANON_ARGS[0];
  d = _FCT_ANON_ARGS[1];
  result = longdiv64(n, d);
  if (isnull(result)) return NULL;

  return result['remainder'];
}

##
# Performs the divide operation on two int64s.  The remainder is discarded
#
# @anonparam n numerator
# @anonparam d denominator
# @remark d
# @return the quotient of n / d
##
function div64()
{
  local_var n, d, result;
  n = _FCT_ANON_ARGS[0];
  d = _FCT_ANON_ARGS[1];
  result = longdiv64(n, d);
  if (isnull(result)) return NULL;

  return result['quotient'];
}
  
##
# Divides an int64
#
# @anonparam n numerator
# @anonparam d divisor
# @remark algorithm from http://en.wikipedia.org/wiki/Division_algorithm
# @return a hash "ret", where
#         ret['quotient'] is the quotient, and
#         ret['remainder'] is the remainder.
#         returns NULL when attempting to divide by zero
##
function longdiv64()
{
  local_var n, d, q, r, i, temp, ni;
  n = _FCT_ANON_ARGS[0]; # numerator
  d = _FCT_ANON_ARGS[1]; # divisor
  q = make_int64(); # quotient
  r = make_int64(); # remainder

  if (d[0] == 0 && d[1] == 0) return NULL; # division by zero
  
  for (i = 63; i >= 0; i--)
  {
    r = lshift64(r, 1);
    temp = rshift64(n, i);
    ni = temp[0] & 1; # the ith bit of the numerator
    if (ni)
      r[0] = r[0] | 1;

    if (gte64(r, d))
    {
      r = sub64(r, d);
      q = add64(q, lshift64(make_int64(low:1), i));
    }
  }

  return make_array('quotient', q, 'remainder', r);
}

##
# Compares the values of two int64s
#
# @param a number to compare
# @param b number to compare
# @param TRUE if a == b,
#        FALSE otherwise
##
function eq64()
{
  local_var a, b;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if (a[1] == b[1] && a[0] == b[0]) return TRUE;

  return FALSE;
}


##
# Does a greater than comparison on two int64s
#
# @param a number to compare
# @param b number to compare
# @param TRUE if a > b,
#        FALSE otherwise
##
function gt64()
{
  local_var a, b;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if (a[1] > b[1])
  {
    return TRUE;
  }

  return a[1] == b[1] && unsigned_gt(a[0], b[0]);
}


##
# Does a greater than comparison on two int64s, assuming they are unsigned
#
# @param a number to compare
# @param b number to compare
# @param TRUE if a > b,
#        FALSE otherwise
##
function unsigned_gt64()
{
  local_var a, b;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if (unsigned_gt(a[1], b[1]))
  {
    return TRUE;
  }
  if (a[1] == b[1] && unsigned_gt(a[0], b[0])) return TRUE;

  return FALSE;
}

##
# Does a greater than comparison on two ints, assuming they are unsigned
#
# @param a number to compare
# @param b number to compare
# @param TRUE if a > b,
#        FALSE otherwise
##
function unsigned_gt()
{
  local_var a, b;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  local_var different_bits;
  different_bits = a ^ b;

  local_var highest_bit_position_only_in_a;
  highest_bit_position_only_in_a = most_significant_set_bit(different_bits & a);

  local_var highest_bit_position_only_in_b;
  highest_bit_position_only_in_b = most_significant_set_bit(different_bits & b);

  return highest_bit_position_only_in_a > highest_bit_position_only_in_b;
}


##
# Returns the position number of the most significant set bit in an integer.
##
function most_significant_set_bit()
{
  local_var x;
  x = _FCT_ANON_ARGS[0];
  if (x == 0)
  {
    return 0;
  }

  local_var mask;
  mask = 0x80000000;

  local_var which_bit;
  which_bit = 32;

  while ((x & mask) == 0)
  {
    mask = mask >> 1;
    which_bit = which_bit - 1;
  }
  return which_bit;
}

##
# Does a greater than or equal to comparison on two int64s
#
# @param a number to compare
# @param b number to compare
# @param TRUE if a >= b,
#        FALSE otherwise
##
function gte64()
{
  local_var a, b;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if (eq64(a, b)) return TRUE;
  return gt64(a, b);
}

##
# Does a less than comparison on two int64s
#
# @param a number to compare
# @param b number to compare
# @param TRUE if a < b,
#        FALSE otherwise
##
function lt64()
{
  local_var a, b;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  return gt64(b, a);
}

##
# Does a less than comparison on two int64s, assuming they are unsigned
#
# @param a number to compare
# @param b number to compare
# @param TRUE if a < b,
#        FALSE otherwise
##
function unsigned_lt64()
{
  local_var a, b;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  return unsigned_gt64(b, a);
}

##
# Does a less than or equal to comparison on two int64s
#
# @param a number to compare
# @param b number to compare
# @param TRUE if a <= b,
#        FALSE otherwise
##
function lte64()
{
  local_var a, b;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if (eq64(a, b)) return TRUE;
  return lt64(a, b);
}

# requires byte_func.inc
#
#function int64_to_hexstr()
#{
#  local_var num;
#  num = _FCT_ANON_ARGS[0];
#
#  return strcat(hexstr(mkdword(num[1])), hexstr(mkdword(num[0])));
#}
