# netscaler_web_cookie_crypto.nasl
# GPLv2
#
# History:
#
# 1.00, 11/21/07
# - Initial release

# Changes by Tenable:
# - Revised plugin title, OSVDB ref (9/23/09)
# - Revised OSVDB reference, added CPE and updated copyright (10/18/2012)
# - Fixed typo in the description (4/25/2014)


include("compat.inc");

if (description)
    {
    script_id(29220);
    script_version("$Revision: 1.9 $");
    script_cve_id("CVE-2007-6192");
    script_osvdb_id(44156);

    script_name(english:"NetScaler Web Management Interface Cookie Credentials Encryption Weakness");

    script_summary(english:"Tests NetScaler web management cookie encryption");
    script_family(english:"Web Servers");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to an information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The version of the Citrix NetScaler web management interface on the
remote host uses weak encryption for protecting the HTTP cookie
content by XORing sensitive values, including the username and
password, with a fixed key stream." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484182/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Do not stay logged into the NetScaler web management interface while
browsing other websites." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_cwe_id(310);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/06");
 script_cvs_date("$Date: 2014/04/25 23:12:41 $");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:netscaler");
 script_end_attributes();

    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (c) 2007-2014 nnposter");
    script_dependencies("netscaler_web_login.nasl");
    script_require_keys("www/netscaler","http/password");
    script_require_ports("Services/www",80);
    exit(0);
    }


include("misc_func.inc");
include("url_func.inc");
include("http_func.inc");

get_kb_item_or_exit("www/netscaler");
get_kb_item_or_exit("http/password");


function cookie_decode (cookie,parm)
{
local_var match;
match=eregmatch(string:cookie,pattern:' '+parm+'=([^; \r\n]*)',icase:TRUE);
if (isnull(match)) return NULL;
return base64_decode(str:urldecode(estr:match[1])-'\n');
}


function str_xor ()
{
local_var nargs,result,len,arg1,arg2,i,j;
nargs=max_index(_FCT_ANON_ARGS);
if (nargs==0) return NULL;
result=_FCT_ANON_ARGS[0];
len=strlen(result);
for (i=1; i<nargs; ++i)
    {
    arg1=result;
    arg2=_FCT_ANON_ARGS[i];
    if (len!=strlen(arg2)) return NULL;
    result="";
    for (j=0; j<len; ++j) result+=raw_string(ord(arg1[j])^ord(arg2[j]));
    }
return result;
}


function strleft ()
{
return substr(_FCT_ANON_ARGS[0],0,_FCT_ANON_ARGS[1]-1);
}


port=get_http_port(default:80);
get_kb_item_or_exit("www/netscaler/"+port);
cookie = get_kb_item_or_exit("/tmp/http/auth/"+port);

hostname=get_host_name();
if (!hostname) hostname=get_host_ip();
keystream=str_xor(hostname,cookie_decode(cookie:cookie,parm:"ns3"));
if (!keystream || strlen(keystream)==0) exit(0);

ns2=cookie_decode(cookie:cookie,parm:"ns2");
ns2len=strlen(ns2);
keylen=strlen(keystream);
if (ns2len<keylen) len=ns2len;
else len=keylen;
guess=str_xor(strleft(ns2,len),strleft(keystream,len));
if (!guess || strlen(guess)==0) exit(0);
if (strleft(get_kb_item("http/password"),len)!=guess) exit(0);

report = string(
    "\n",
    "Sensitive values, including the username and password, can be\n",
    "decrypted by XORing the plaintext with the following fixed key\n",
    "stream :\n",
    "\n",
    hexstr(keystream), "..."
);
security_warning(port:port, extra:report);
