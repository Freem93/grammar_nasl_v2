#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11972);
 script_version ("$Revision: 1.21 $");
 script_bugtraq_id(9310);
 script_osvdb_id(3304);
 script_xref(name:"Secunia", value:"10517");

 script_name(english:"miniBB bb_func_usernfo.php Website Name Field XSS");
 script_summary(english:"Determine if MiniBB can be used to execute arbitrary commands");

 script_set_attribute( attribute:"synopsis", value:
"A web application on the remote host has a cross-site scripting
vulnerability." );
 script_set_attribute(attribute:"description",  value:
"The remote host is using the miniBB forum management system.
According to its version number, this forum is vulnerable to a
cross-site scripting bug.  A remote attacker could exploit
this to impersonate a legitimate user by tricking them into
requesting a maliciously crafted URL." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2003/Dec/709"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/30");
 script_cvs_date("$Date: 2016/11/18 19:03:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1);

foreach d (cgi_dirs())
{
 url = string(d, "/index.php");
 buf = http_get_cache(item:url, port:port, exit_on_fail: 1);

 str = egrep(pattern:"Powered by.*miniBB", string:buf);
 if( str )
   {
    version = ereg_replace(pattern:".*Powered by.*miniBB (.*)</a>.*", string:str, replace:"\1");
    if ( d == "" ) d = "/";

    set_kb_item(name:"www/" + port + "/minibb", value:version + " under " + d);

    if ( ereg(pattern:"^(0\.|1\.[0-6][^0-9]|7[^a-z])", string:version) )
     {
     security_warning(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
     exit(0);
     }
   }
}
