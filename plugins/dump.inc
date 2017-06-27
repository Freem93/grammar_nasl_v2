#TRUSTED aa7853e4a525abca4967a0be2fc15e5609253767f33919830a9a88b49296d7cc9a2e9e2cd2f60c85b9837ec9b5d6a9c3b42e107fe53f810bb671294914cffb530c9c3e778a23d6fc73efd1b1f89d7fc221fde08026d2e99074fe79f4257c4bdfdf8622a5c83e5a429c170d784550186f168cb3cf140dd5e7c28873fca7394e010acf601045c84c1825de748a51e3829cd58adfc88db89fe69029ff5ecb22226cd7d43975cddb831eadf140937cdee70c1260335477925b6b11f160c6197a30a5a0c5c6804260b7162412ede3961afc4fd4627c0313edc03050faf53068a4e9e63a376e41b021c3a29b7b1d687e4e0198ee0a3039251915f8adadf3702b8471c09f228ba23efd153bec3459dfbd5417009af3e0767a517624d53274213b52669689aa8a26f12e91066b4adf9dd16399f334fc107671265bf419fdda095baa9e1395c1fd4bac1bfe0e24568c1367d861ea6ff34c464e2dc339f0cdbd550904874bb383b9258f2af173524d1267a8607486954fc3f669c027b7272d5a9ec9d279573ef57e9f57e8dadee636688544e9b9b7ea1a716f2c332b8595b317431580f203b639ceab1edd9a4be5fd21f01475e0bb918aa73db116ec1b1b8cb828089c5562463709ff0bf53f66afd6f3f9c0b359ade7b7f25f252d67e64f2f63b66eaa6bfc39dbe3424d4b503ccf31ee6b773bb8b2525bbcf3b1058a73fdca81a813e6fb72
###
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
# 
#
# An earlier iteration of this file was written by George Dagousset (2002)
#
# This include file is released under the terms of the GPLv2
#
# This include file has functions used to generate a hex dump of data
# 
# dump.inc
# Revision: 1.11
###

##
# Generates the hex line number prefix for line "line" of "linenumber".
#
# This function is used by hexdump() to generate the line numbering for its output
#
# For example, the 0th line of 5 will result in "0x00: "
# The 5th line of 500 will result in "0x0040: "
# The amount of padding each offset receives depends on "linenumber" - numbers
# will be padded out (if necessary) so they are the same length as the largest
# possible number.
#
# @line the number of the current line
# @linenumber the total number of lines
# @return a line number prefix to be used by hexdump()
##
function line2string (line, linenumber)
{
 local_var tmp, pos;

 line = line*16;
 tmp = raw_string (
	(line >> 24) & 0xFF,
	(line >> 16) & 0xFF,
	(line >> 8) & 0xFF,
	(line ) & 0xFF
	);

 if (linenumber < 256)
   pos = 3;
 else if (linenumber < 65536)
   pos = 2;
 else if (linenumber < 16777216)
   pos = 1;
 else
   pos = 0;

 return string ("0x", toupper(hexstr(substr (tmp, pos, 3))), ": ");
}


##
# Determines if the given character is ASCII suitable to be displayed in hexdump()
# output (0x20 through 0x7e inclusive).  This excludes control characters such as
# tab and newline.
#
# @param c character to check
# @return TRUE if "c" is between 0x20 and 0x7e inclusive,
#         FALSE otherwise
##
function isprint (c)
{
 if ( (ord(c) >= 0x20) && (ord(c) <= 0x7E) )
   return TRUE;

 return FALSE;
}


##
# does a hex dump of sixteen bytes of data
#
# @str hex data to dump
# @line the number of the line being dumped
# @totallen the total number of lines in the dump
# @return a hex dump of "hex" with a line number prefix
##
function dump_line_and_data(str, linenb, totallen)
{
  local_var	j, len, c, line, data;

  line = line2string (line: linenb, linenumber: totallen);
  len = strlen(str);

  for (j = 0; j < 16; j++)
  {
   if (j < len )
   {
    line = strcat(line, " ", toupper(hexstr(str[j])));
    c = str[j];
    if (isprint (c:c))
      data += c;
    else
      data += ".";
   }
   else
   {
    line += "   ";
    data += " ";
   }
  }
  return  strcat(line, '    ', data, '\n');
}

##
# does a hex dump of the given data
#
# @param ddata the data to dump
# @return a hex dump of "ddata"
##
function hexdump (ddata)
{
 local_var tmp, i, linenumber, len;
 local_var	same_str_cnt, prev_str, prev_adr, str;

 len = strlen(ddata);
 linenumber = len / 16;

 prev_str = NULL; same_str_cnt = 0; prev_adr = 0;

 for (i = 0; i <= linenumber; i++)
 {
  str = substr(ddata, i*16, i*16+15);
  if (! isnull(prev_str))
  {
    if (str == prev_str)
    {
      same_str_cnt ++;
      continue;
    }
#    else if (same_str_cnt == 1)
#    {
#      tmp += dump_line_and_data(str: prev_str, linenb: i-1, totallen: len);    
#    }
#    else if (same_str_cnt > 1)
    else if (same_str_cnt >= 1)
      tmp += '*\n';    
  }
  prev_str = str; same_str_cnt = 0;
  tmp += dump_line_and_data(str: str, linenb: i, totallen: len);
 }

 if (same_str_cnt > 0)	# Should not happen!
   tmp += dump_line_and_data(str: prev_str, linenb: i-1, totallen: len);
 return tmp;
}
 

##
# Displays a hex dump of the given data
#
# @dtitle a string title to give to the hex dump
# @ddata the data to dump
##
function dump( dtitle, ddata )
{
 if( ! isnull( dtitle ) )
	display('---[ ' + dtitle + ' ]---\n' );


 display(hexdump(ddata:ddata));
}

##
# A debug function that recursively prints out a table.
#
# @param table The table to print.
# @param indent [optional] Used internally for recursion.
##
function dump_table(table, indent)
{
  local_var key;

  if(!indent)
    indent = 0;

  if(typeof(table) == 'array')
  {
    foreach key(keys(table))
    {
      if(typeof(table[key]) == 'array')
      {
        display(crap(data:'\t', length:indent), key, ':\n');
        dump_table(table:table[key], indent:indent+1);
      }
      else
      {
        display(crap(data:'\t', length:indent), key, ': ', table[key], '\n');
      }
    }
  }
  else
  {
    display(crap(data:' ', length:indent), '\n');
  }
}

