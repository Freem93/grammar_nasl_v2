#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
if (description)
{
  script_id(50413);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2010-3332");
  script_bugtraq_id(43316, 44285);
  script_osvdb_id(68127);
  script_xref(name:"MSFT", value:"MS10-070");

  script_name(english:"CGI Generic Padding Oracle");
  script_summary(english:"Generic padding oracle detection");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote server is potentially prone to
a padding oracle attack"
  );

  script_set_attribute(
    attribute:"description",
    value:
"By manipulating the padding on an encrypted string, Nessus was able
to generate an error message that indicates a likely 'padding oracle'
vulnerability.  Such a vulnerability can affect any application or
framework that uses encryption improperly, such as some versions of
ASP.net, Java Server Faces, and Mono. 

An attacker may exploit this issue to decrypt data and recover
encryption keys, potentially viewing and modifying confidential data. 

Note that this plugin should detect the MS10-070 padding oracle
vulnerability in ASP.net if CustomErrors are enabled in that."
  );
  script_set_attribute(
    attribute:"solution",
    value: 
"Update the affected server software, or modify the CGI scripts so
that they properly validate encrypted data before attempting
decryption."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://netifera.com/research/");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-070");
  script_set_attribute(attribute:"see_also", value:"http://www.mono-project.com/Vulnerabilities#ASP.NET_Padding_Oracle");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=623799");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/09/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencie("webmirror.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("byte_func.inc");
include("url_func.inc");
include("torture_cgi_func.inc");

# Define encoding constants
ENCODING_BASE64 = 1;
ENCODING_BASE64_URL = 2;
ENCODING_HEX = 3;

# Define the strings that indicate vulnerability. These will only trigger if they're found by switching
# the last bit, not the first bit or no bits, so they can be somewhat general. 
VULN_STRINGS = make_list('padding', 'runtime', 'runtime error', 'server error', 'cryptographicexception', 'crypto');

# Keep track of what we've already tested so we don't repeat checks
cache = make_list();

# If this is still FALSE at the end of execution, don't display the exit message
vulnerable = '';
found_encrypted = FALSE;

# Decode a URL-encoded Base64 string (used by ASP.net). Basically, it's base64 with different
# symbols, and with an integer for padding instead of equal signs. 
function base64url_decode(str)
{
  local_var cstr,padlen;
 
  # strip last char
  cstr = substr(str, 0, strlen(str) - 2);
 
  # num of '=' to pad
  padlen = str[strlen(str) -1];
 
  cstr = str_replace(string:cstr, find:"-",replace:"+");
  cstr = str_replace(string:cstr, find:"_",replace:"/");
  cstr += crap(data:"=",length:padlen);
 
  return base64_decode(str:cstr);
}

function base64url_encode(str)
{
  local_var cstr, idx, padchars;
 
  cstr = base64(str:str);
 
  # look for '='
  idx = stridx(cstr,"=");
 
  if(idx != -1)
  {
    padchars  = substr(cstr, idx, strlen(cstr) -1);
 
    cstr      = substr(cstr, 0, idx -1);
    cstr      += strlen(padchars);
  }
  else # no padding
    cstr += "0";
 
  cstr = str_replace(string:cstr, find:"+",replace:"-");
  cstr = str_replace(string:cstr, find:"/",replace:"_");
 
  return cstr;
}

# Decide if the data given in 'data' is encrypted
#
# It turns out that this is difficult to do on short strings, so we are going to 
# solve this by cheating. Basically, check if the string contains any non-ascii
# characters (<0x20 or >0x7F). The odds of a 4-character encrypted string having
# at least one character that falls outside of ASCII is almost 100%. We also 
# ignore any string longer than 16 bytes, since those are generally too short
# to be encrypted. 
function is_encrypted(data)
{
  local_var non_ascii, i, b;

  # Make sure we have a reasonable sized string (encrypted strings tend to be long, and short strings tend to 
  # break our numbers)
  if(strlen(data) < 16)
    return FALSE;

  non_ascii = 0;
  for(i = 0; i < strlen(data); i++)
  {
    b = getbyte(blob:data, pos:i);
    if(b < 0x20 || b > 0x7F)
      non_ascii++;
  }

  return (non_ascii > (strlen(data) / 4));
}

# All encrypted CGI arguments have an encoding. Here is what I've found so far:
# ASP.net .axd files - base64-url
# ASP.net __VIEWSTATE - base64
# Mono .axd files - hex
# Mono __VIEWSTATE - hex
#
# We give priority to hex. If a string has an even number of characters in the range 0-9 and A-F, we call
# it hex and don't try Base64. It's fairly unlikely that a reasonably sized base64 string would be exclusively
# hex characters. 
#
# Base64 and Base64 URL are a little more difficult to distinguish. In *most* cases, we're okay, but once in awhile 
# it may be decoded incorrectly, in which case two different encodings are returned. 
function decode(data)
{
  local_var decoded_str, decoded;
  decoded = make_array();

  # Get rid of strings that are all numeric (they probably aren't encoded and they pollute our results)
  if(ereg(string:data, pattern:"^[0-9]+$"))
  {
    return NULL;
  }

  # Hex strings are a-fA-F0-9. Although it's technically possible for a base64 string to look like this,
  # it's exceptionally unlikely.
  if(ereg(string:data, pattern:"^([a-fA-F0-9]{2})+$"))
  {
    decoded_str = hex2raw(s:data);
    if(decoded_str)
    {
      decoded[ENCODING_HEX] = decoded_str;
      return decoded;
    }
  }


  # base64url always has an integer 0, 1, or 2 at the end, and contains letters, numbers, -, and _. The
  # final byte is the number of padding bytes, so the string length with a number of extra bytes equal
  # to the final digit has to be a multiple of 4. 
  if(ereg(string:data, pattern:"^[a-zA-Z0-9_-]+[012]$"))
  {
    # The last letter represents the length
    if(((strlen(data) - 1 + int(data[strlen(data)-1])) % 4) == 0)
    {
      decoded_str = base64url_decode(str:data);

      if(decoded_str)
        decoded[ENCODING_BASE64_URL] = decoded_str;
    }
  }

  # base64 strings are similar, except they can contain + and /, and end with 0 - 2 '=' signs. They are
  # also a multiple of 4 bytes. 
  if(ereg(string:data, pattern:"^[a-zA-Z0-9/+]+={0,2}$") && (strlen(data) % 4) == 0)
  {
    decoded_str = base64_decode(str:data);
    if(decoded_str)
      decoded[ENCODING_BASE64] = decoded_str;
  }

  if(max_index(keys(decoded)) == 0)
    return NULL;
  return decoded;
}

function encode(data, encoding)
{
  if(encoding == ENCODING_BASE64_URL)
    return base64url_encode(str:data);

  if(encoding == ENCODING_BASE64)
    return base64(str:data);

  if(encoding == ENCODING_HEX)
    return hexstr(data);

  exit(0, "Unknown encoding type was passed to encode(): " + encoding);
  return NULL;
}

function go(port, page, new_arg, new_value)
{
  local_var query, arg_value, res;
  local_var arg, args, arg2;

  # First, we need to get all the arguments for the page
  query = page + '?';

  # Then get all the arguments, and replace the one we want
  args = get_cgi_arg_list(port: port, cgi: page);
  if (max_index(args) == 0)
    exit(0, "Couldn't get args list"); # Shouldn't ever happen (we already did this check)

  foreach arg(args)
  {
    arg2 = replace_cgi_1arg_token(port: port, arg: arg);
    if (arg2 == new_arg)
    {
      query = query + arg2 + "=" + urlencode(str:new_value) + "&";
    }
    else
    {
      arg_value = get_cgi_arg_val_list(port: port, cgi: page, arg: arg);
      if(max_index(arg_value) == 0 || !arg_value[0])
        arg_value = make_list('');

      query = query + arg2 + "=" + urlencode(str:arg_value[0]) + "&";
    }
  }
  query = substr(query, 0, strlen(query)-2);

  res = http_send_recv3(method:'GET', item:query, port:port, fetch404:TRUE, exit_on_fail:TRUE);

  return res;
}

function do_check(port, page, arg, value, encoding)
{
  local_var temp, test_values, i;
  local_var result, test_results;
  local_var vuln_string;

  test_values = make_list();
  test_results = make_list();

  test_values[0] = value;

  # The second test is going to change the first bit
  temp = value;
  temp[0] = raw_string(ord(value[0]) ^ 1);
  test_values[1] = temp;

  # The first test is going to change the last bit
  temp = value;
  temp[strlen(value)-1] = raw_string(ord(value[strlen(value) - 1]) ^ 1);
  test_values[2] = temp;

  # Encode all the values using the given encoding
  for(i = 0; i < max_index(test_values); i++)
  {
    test_values[i] = encode(data:test_values[i], encoding:encoding);
    result = go(port:port, page:page, new_arg:arg, new_value:test_values[i]);
    test_results[i] = tolower(result[0] + result[1] + result[2]);
  }

  # If the control test returned an error, then keep going
  if('200' >!< test_results[0])
    return;

  # Check if changing the last bit produced a result that changing the first bit didn't. These results are based
  # on a list of error strings. 
  foreach vuln_string(VULN_STRINGS)
  {
    if(vuln_string >< test_results[2] && vuln_string >!< test_results[1] && vuln_string >!< test_results[0])
    {
      vulnerable += '  - ' + page + ' [arg=' + arg + ']\n';
      return TRUE;
    }
  }
}

function try_check(port, page, arg, value)
{
  local_var cached;
  local_var decoded, data;
  local_var key;

  # Check if we've already looked at this argument
  foreach cached(cache)
    if(cached == value)
      return;

  cache = make_list(cache, value);

  # Try decoding the argument
  decoded = decode(data:value);

  if(decoded)
  {
    # Loop through the possible encryptions
    foreach key(keys(decoded))
    {
      if(is_encrypted(data:decoded[key]))
      {
        found_encrypted = TRUE;
        do_check(port:port, page:page, arg:arg, value:decoded[key], encoding:key);
        if (vulnerable && !thorough_tests) break;
      }
    }
  }
}

port = get_http_port(default:80, embedded: 0);

# Get a list of all CGI files. If CGI scanning is turned off, we give up and die
if (get_kb_item("Settings/disable_cgi_scanning"))
  exit(0, "CGI scanning is disabled.");

cgi = get_cgi_list(port: port);
if (isnull(cgi)) exit(0, "Couldn't find any web applications on the web server on port "+port+".");

# Look for a CGI with an encrypted argument
foreach file (cgi)
{
  cgi_args = get_cgi_arg_list(port: port, cgi: file);
  if(max_index(cgi_args) > 0)
  {
    foreach cgi_arg(cgi_args)
    {
      values = get_cgi_arg_val_list(port: port, cgi: file, arg: cgi_arg);
      if(max_index(values) > 0)
      {
        cgi_arg = replace_cgi_1arg_token(port: port, arg: cgi_arg);
        try_check(port:port, page:file, arg:cgi_arg, value:values[0]);
        if (vulnerable && !thorough_tests) break;
      }
    }
  }
}

if(vulnerable) 
{
  if (report_verbosity > 0)
  {
    if (max_index(split(vulnerable)) > 1)
    {
      s = "s";
      are = "are";
    }
    else 
    {
      s = "";
      are = "is";
    }

    report = 
      '\n' +
      'The following page'+s+' / argument'+s+' '+are+' potentially affected :\n' +
      '\n' +
      vulnerable;
    if (!thorough_tests)
      report += 
        '\n' +
        'Note that Nessus stopped searching after one affected script was found.\n' +
        'For a complete scan, enable the \'Perform thorough tests\' setting and\n' +
        're-scan.\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else if(found_encrypted)
  exit(0, "The web server on port " + port + " appears to use encrypted data and appears unaffected.");
else
  exit(0, "The web server on port " + port + " does not appear to use encrypted data so no checks were performed.");
