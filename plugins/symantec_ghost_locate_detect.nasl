#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(25490);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2012/08/01 21:10:57 $");
 script_name(english:"Symantec Ghost Solution Locate Server Detection");
 script_set_attribute(attribute:"synopsis", value:
"An OS deployment server is running on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the 'locate' service of Symantec Ghost
solution, an OS deployment and management solution. 

This service is used by clients to discover management servers or to
test if the main server is alive." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:ghost_solutions_suite");
script_end_attributes();

 script_summary(english:"Determine if a remote host is running Symantec Ghost Solution Status Service");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
 script_require_ports(1345);
 exit(0);
}


include ("byte_func.inc");


global_var __stream, __stream_pos, __stream_length, __stream_idx, _data_type;


STRING_CODE = 0x33;
STRUCT_CODE = 0x22;
LIST_CODE   = 0x21;
BLOB_CODE   = 0x20;
UINT_CODE   = 0x0B;
SINT_CODE   = 0x09;
INT_CODE    = 0x08;
VOID_CODE   = 0x00;
END_CODE    = 0x02;


_data_type = NULL;
_data_type["Name"]           = LIST_CODE;
_data_type["Uuid"]           = BLOB_CODE;
_data_type["Sequence"]       = INT_CODE;
_data_type["Idle"]           = VOID_CODE;
_data_type["Platform"]       = STRING_CODE;
_data_type["Version"]        = INT_CODE;
_data_type["Build"]          = INT_CODE;
_data_type["IPADDRESS"]      = INT_CODE;
_data_type["SUBNETMASK"]     = INT_CODE;
_data_type["ProductVersion"] = STRING_CODE;



function mklist()
{
 local_var ret;
 local_var i, l;

 l = max_index (_FCT_ANON_ARGS);

 if (NASL_LEVEL >= 3000)
   ret  = fill_list(length:l, value:0);
 else
   ret = NULL;

 for (i=0 ; i<l ; i++)
   ret[i] = _FCT_ANON_ARGS[i];

 return ret;
}


function mkipaddr()
{
 local_var ip;
 local_var str;

 ip = _FCT_ANON_ARGS[0];
 str = split(ip, sep:'.', keep:FALSE);
 return 
	(int(str[0]) << 24) +
	(int(str[1]) << 16) +
	(int(str[2]) << 8) +
	int(str[3]) ; 
}


function stream_init(data)
{
 __stream = data;
 __stream_pos = 0;
 __stream_length = strlen(data);
 __stream_idx = 1;
}


function stream_getByte()
{
 if (__stream_pos >= __stream_length)
   exit(0);

 return ord(__stream[__stream_pos++]);
}


function stream_putByte()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 __stream += mkbyte(l);
}


function stream_putData()
{
 local_var d;
 d = _FCT_ANON_ARGS[0];

 __stream += d;
}


function putUTF8Number()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if (l <= 0x7F)
   stream_putByte(l);
 else
 {
  if (l > 0x7FF)
  {
   if (l > 0xFFFF)
   {
    if (l > 0x1FFFFF)
    {
     if (l > 0x3FFFFFF)
     {
      stream_putByte( ((l >>> 30) & 0x01) + 0xFC );
      stream_putByte( ((l >>> 24) & 0x3F) + 0x80 );
     }
     else
       stream_putByte( ((l >>> 24) & 0x03) + 0xF8 );

     stream_putByte( ((l >>> 18) & 0x3F) + 0x80 );
    }
    else
      stream_putByte( ((l >>> 18) & 0x07) + 0xF0 );

    stream_putByte( ((l >>> 12) & 0x3F) + 0x80 );
   }
   else
    stream_putByte( ((l >>> 12) & 0x0F) + 0xE0 );

   stream_putByte( ((l >>> 6) & 0x3F) + 0x80 );
  }
  else
   stream_putByte( ((l >>> 6) & 0x1F) + 0xC0 );

  stream_putByte( (l & 0x3F) + 0x80 );
 }
}


function getUTF8Number()
{
 local_var num, b;

 b = stream_getByte();

 if (b & 0x80)
 {
  num = stream_getByte() & 0x3F;

  if (b & 0x20)
  {
   num = (num << 6) + (stream_getByte() & 0x3F);

   if (b & 0x10)
   {
    num = (num << 6) + (stream_getByte() & 0x3F);

    if (b >= f5 && b <= 0xf7)
    {
     if (b == 0xf6)
       num = ((b & 0x01) << 18) + num;     
    }
    else if (b >= 0xf8 && b <= 0xfd)
    {
     num = (num << 6) + (stream_getByte() & 0x3F);

     if (b >= 0xfc && b <= 0xfd)
     {
      num = (num << 6) + (stream_getByte() & 0x3F);

      num = num + ((b & 0x03) << 30);
     }
     else
       num = ((b & 0x03) << 24) + num;
    }
    else
      num = ((b & 0x07) << 18) + num;
   }
   else
     num = ((b & 0x0F) << 12) + num;
  }
  else
    num = ((b & 0x1F) << 6) + num;
 }
 else
  num = b & 0x7F;

 return num;
}


function findDataType(data)
{
 return _data_type[data];
}


function putNumber()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 putUTF8Number(l);
}


function putSInt(i)
{
 if (i < 0)
 {
  putNumber(UINT_CODE);
  i -= 0x80000000;
 }
 else
   putNumber(SINT_CODE);

 putUTF8Number(i);
}


function putIndex()
{
 putNumber(0x24);
 putNumber(0x02);
 putNumber(0x02);
 putSInt(i:__stream_idx++);
}


function putIndexEnd(idx)
{
 putNumber(0x0C);
 putNumber(idx);
}


function putSBlob(b)
{
 putNumber(BLOB_CODE);
 putNumber(strlen(b));
 stream_putData(b);
}


function putSString(s)
{
 local_var idx;

 idx = __stream_idx;

 putIndex();

 putNumber(STRING_CODE);
 putNumber(strlen(s));
 stream_putData(s);

 putIndexEnd(idx:idx);
}


function putSList(l)
{
 local_var type, elem;

 putNumber(LIST_CODE);
 putNumber(0);
 putNumber(0);

 foreach elem (l)
 {
  type = elem[0];

  if (type == STRING_CODE)
    putSString(s:elem[1]);
  else if (type == INT_CODE)
    putSInt(i:elem[1]);
  else if (type == BLOB_CODE)
    putSBlob(b:elem[1]);
  else if (type == LIST_CODE)
    putSList(l:elem[1]);
  else if (type == STRUCT_CODE)
    putSStruct(s:elem[1]);
 }

 putNumber(END_CODE);
}


function putSStruct(s)
{
 local_var type, elem;

 putNumber(STRUCT_CODE);
 putNumber(0x01);
 putNumber(0x00);

 foreach elem (s)
 {
  type = findDataType(data:elem[0]);

  if (type == VOID_CODE)
  {
   putNumber(0x0C);
   putNumber(0x01);
  }

  putSString(s:elem[0]);

  if (type == STRING_CODE)
    putSString(s:elem[1]);
  else if (type == INT_CODE)
    putSInt(i:elem[1]);
  else if (type == BLOB_CODE)
    putSBlob(b:elem[1]);
  else if (type == LIST_CODE)
    putSList(l:elem[1]);
  else if (type == STRUCT_CODE)
    putSStruct(s:elem[1]);
 }

 putNumber(END_CODE);
}



### Main Code ###


port = 1345;

if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit(0);


stream_init(data:"");

l = NULL;
l[0] = mklist(BLOB_CODE, "AAAAAA");

s = NULL;
s[0] = mklist("Name", l);
s[1] = mklist("Uuid", "BBBBBBBBBBBBBBBB");
s[2] = mklist("Sequence", 185212261);
s[3] = mklist("Idle");
s[4] = mklist("Platform", "Win2k");
s[5] = mklist("Version", 720896);
s[6] = mklist("Build", 67068);
s[7] = mklist("IPADDRESS", mkipaddr(this_host()));
s[8] = mklist("SUBNETMASK", 0xFFFFFF00);
s[9] = mklist("ProductVersion", "110.01.153");


putSString(s:"Status");
putSStruct(s:s);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


send(socket:soc, data:__stream);
buf = recv(socket:soc, length:4096);

if ("Locate_Error" >< buf)
  security_note(port:port, protocol:"udp");
