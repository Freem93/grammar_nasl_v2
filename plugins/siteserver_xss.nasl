
# Changes by Tenable :
# - Updated to use compat.inc (11/20/2009)

include("compat.inc");

if (description)
{
  
  script_id(33928);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2002-2073");
  script_bugtraq_id(3999);
  script_osvdb_id(17666);

  script_name(english:"MS Site Server < 3.0 formslogin.asp url Parameter XSS");
  script_summary(english:"Checks for an Cross-Site Scripting flaw in formslogin.asp, part of Microsoft Site Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The script 'formslogin.asp' fails to sanitize the 'url' parameter. 
This allows remote attackers to inject arbitrary web scripts or HTML." );
 #https://web.archive.org/web/20020228224829/http://archives.neohapsis.com/archives/vulnwatch/2002-q1/0033.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bc870f9");
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or upgrade to a unaffected version." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/30");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Westpoint Ltd");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# Run against working web services
port = get_http_port(default:80);

if ( get_kb_item(strcat("www/", port, "/generic_xss")) ||
   ! can_host_asp(port: port) ) exit(0);

# Build the exploit string
exploit=string("><script>alert('Vulnerable');</script>");
url=string("/_mem_bin/formslogin.asp?url=", exploit);

request = http_get(item:url, port:port);
response = http_keepalive_send_recv(port:port, data:request, bodyonly:TRUE);

if(response == NULL) exit(0);

# There's a problem if we see our exploit in the response.
if (exploit >< response && egrep(pattern:'^HTTP/[01.]+ +200 ', string:response))
{  
        set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        desc = strcat('\n',build_url(port:port, qs:url));
        security_warning(port:port, extra:desc);
        exit(0);
}
