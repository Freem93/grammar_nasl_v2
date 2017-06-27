#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50546);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");
   
  script_cve_id("CVE-2010-4184");
  script_bugtraq_id(44629);
  script_osvdb_id(69014);
  script_xref(name:"CERT", value:"465239");
  script_xref(name:"Secunia", value:"42104");

  script_name(english:"NetSupport Manager Gateway HTTP Protocol Information Disclosure");
  script_summary(english:"Looks for unencrypted CMD response");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server hosts an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description",value:
"The NetSupport Manager Gateway install on the remote host supports
unencrypted communication with NetSupport Manager controls and
clients.  By monitoring traffic between NetSupport Manager controls,
clients and the gateway, it may be possible for an attacker to gain
sensitive information about the client machine.");
   # http://www.netsupportsoftware.com/support/kb/asp/kbprovider.asp?gettd=634&lang=EN&xsl=http%3A//www.netsupportsoftware.com/support/kb/TechDoc.xsl
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?92cb9630");
  script_set_attribute(attribute:"solution",value:
"Upgrade to NetSupport Manager 11.00.0005 or later, and consider
blocking communication with NetSupport Manager clients and controls
that do not support encryption.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/08"); 
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netsupportsoftware:netsupport_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("netsupport_gateway_detect.nasl");
  script_require_ports("Services/www", "Services/netsupport-gateway", 443);
  script_require_keys("Services/netsupport-gateway");
 
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_service(svc:"netsupport-gateway", exit_on_fail:TRUE);

cmd = 'CMD=OPEN\r\nCLIENT_VERSION=1.0\r\nPROTOCOL_VER=1.1\r\n';

# *required otherwise http API breaks against this webserver.
http_disable_keep_alive();

# nb: 
#   Webserver response is erratic
# - Won't respond to GET requests
# - Won't respond if User-Agent is not recognized
# - Only responds to /fakeurl.htm POST request.
# - Can take some time to respond.

http_set_read_timeout(2 * get_read_timeout());

res = http_send_recv3(
        method:"POST", 
        item:"/fakeurl.htm", 
        version:11,
        port: port,
        add_headers: make_array('User-Agent', 'NetSupport Manager/1.0'),
        data: cmd);

# If we see plaintext CMD response, then report.

if (
  "CMD=OPEN_REPLY" >< res[2] && 
  "SERVER_VERSION=" >< res[2] && 
  "MAXPACKET=" >< res[2] && 
  "CMPI=" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    req = http_last_sent_request();
    report = '\n' +
      'Nessus was able to verify this issue using the following request :\n' +
      '\n' +
      str_replace(find:'\n', replace:'\n  ', string:req);

    if(report_verbosity > 1)
      report += '\n'+
        "Here's the response to the above request : "+ '\n\n'+
        res[2];

    if (get_kb_item("netsupport-gateway/" + port + "/encrypted_communication"))
      report += '\n' +
        "Note that the remote gateway supports encrypted communication,"       + '\n' +
        "however it still allows unencrypted communication with old versions"  + '\n' +
        "of NetSupport Manager controls and clients. Enable 'Block any remote" + '\n' +
        "computers not using encrypted communications' feature to block"       + '\n' +
        "communication with clients that do not support encryption."           + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
} 
else exit(0, "The NetSupport Manager Gateway listening on port " + port + " is not affected.");
