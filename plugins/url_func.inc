# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# uri_func.inc
# $Revision: 1.10 $
#
# @NOGPL@
#


##
# url_hex2raw is identical to hex2raw from misc_func.inc apart from its name.
##
function url_hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);	# remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2)
 {
  display("url_hex2raw: odd string: ", s, "\n");
  l--;
 }
 s = tolower(s);
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}


##
# URL decodes the given string
#
# This function assumes 'estr' is encoded per RFC 2396 / 2732 and decodes it.
#
# @param estr URL encoded string
# @return decoded version of "estr"
##
function urldecode(estr)
{
  local_var ch, len, i, str;

  str = "";
  len = strlen(estr);

  i = 0;
  while (i < len)
  {
    ch = estr[i];
    if (ch == "+") ch = " ";

    if (ch == "%" && substr(estr, i+1, i+2) =~ "^[0-9a-fA-F]{2}$")
    {
      # nb: url_hex2raw() expects only lowercase hex digits!
      str += url_hex2raw(s:tolower(substr(estr, i+1, i+2)));
      i += 2;
    }
    else str += ch;
    i++;
  }

  return str;
}


global_var HEX_LOWERCASE, HEX_UPPERCASE;

HEX_LOWERCASE = 1;
HEX_UPPERCASE = 2;

##
# URL encodes the given string
#
# 'str' is encoded per RFC 2396 / 2732
#
# @param str string to URL encoded
# @param unreserved a string containing characters that should not be encoded. this parameter
#        is optional - if no argument is provided, the default is used (alphanumeric and _.!~*'()-])
# @case_type if HEX_UPPERCASE, specifies hex of encoded characters should be upper case. otherwise, all hex is lowercase
#
# @return URL encoded version of "str"
##
function urlencode(str, unreserved, case_type)
{
  local_var ch, estr, len, i;

  estr = "";
  len = strlen(str);
  if (isnull(unreserved)) unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]";
  if (isnull(case_type)) case_type = HEX_LOWERCASE;

  for (i=0; i<len; i+=1)
  {
    ch = str[i];

    if (ch >< unreserved) estr += ch;
    # the rest are escaped.
    else
    {
      ch = hexstr(ch);
      if (case_type == HEX_UPPERCASE)
        ch = toupper(ch);
      estr += "%" + ch;
    }
  }

  return estr;
}
