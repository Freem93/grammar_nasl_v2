#
# (C) Tenable Network Security, Inc.
#

#
# Source: cross_site_scripting.nasl
#


include("compat.inc");

if (description)
{
 script_id(11634);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2015/02/11 21:07:50 $");

 script_cve_id("CVE-2003-0292");
 script_bugtraq_id(7596);
 script_osvdb_id(6795);

 script_name(english:"Proxy Web Server XSS");
 script_summary(english:"Determine if the remote proxy is affected by a cross-site scripting vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is prone to cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a proxy web server that fails to adequately
sanitize request strings of malicious JavaScript.  By leveraging this
issue, an attacker may be able to cause arbitrary HTML and script code
to be executed in a user's browser within the security context of the
affected site." );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_dependencies("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www", "Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

exts =  make_list(".jsp", ".shtml", ".thtml", ".cfm");
xss = "<SCRIPT>alert('Vulnerable')</SCRIPT>";

port = get_kb_item("Services/http_proxy");
if (! port) port = 3128;
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");

foreach e (exts)
{
  rq = http_mk_proxy_request(scheme: "http", method: "GET", item: "/"+xss+e, 
     host: "xxxxxxxxxxx.", port: 80, version: 10);

  w = http_send_recv_req(port:port, req: rq, exit_on_fail: 1);
  txt = extract_pattern_from_resp(string: w[2], pattern: xss, code: "ST:");
  if (strlen(txt) > 0)
  {
    set_kb_item(name: "www_proxy/"+port+"/generic_xss", value:TRUE);
    if (report_verbosity <= 0)
      security_warning(port: port);
    else
    {
      e = '\nThe following request :\n\n' + crap(data: '-', length: 66) +'\n';
      e += http_last_sent_request();
      e += crap(data: '-', length: 66) +'\n\nproduced the following XSS :\n\n';
      e += crap(data: '-', length: 66) + '\n';
      e += txt;
      e += crap(data: '-', length: 66) + '\n';
      security_warning(port: port, extra: e);
    }
    exit(0);
  }
}

exit(0, "The remote proxy on port "+port+" is not vulnerable.");
