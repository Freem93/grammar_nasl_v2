#
# (C) Tenable Network Security, Inc.
#
# Initial version written by John Lampe

include("compat.inc");

if (description)
{
 script_id(10657);
 script_version("$Revision: 1.45 $");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");

 script_cve_id("CVE-2001-0241");
 script_bugtraq_id(2674);
 script_osvdb_id(3323);
 script_xref(name:"CERT", value:"516648");
 script_xref(name:"CERT-CC", value:"CA-2001-10");
 script_xref(name:"MSFT", value:"MS01-023");

 script_name(english:"MS01-023: Microsoft IIS 5.0 Malformed HTTP Printer Request Header Remote Buffer Overflow (953155) (uncredentialed check)");
 script_summary(english:"Makes sure that MS01-023 is installed on the remote host");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host thru IIS.");
 script_set_attribute(attribute:"description", value:
"The remote version of the IIS web server contains a bug which might be
used by an attacker to execute arbitrary code on the remote system.

To exploit this vulnerability, an attacker would need to send a
malicious HTTP/1.1 request to the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms01-023");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS01-023 Microsoft IIS 5.0 Printer Host Header Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?faa4ec33");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/05/01");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/05/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/05/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (report_paranoia < 2)
{
  server_name = http_server_header(port:port);
  if (server_name)
  {
    if ("Microsoft-IIS" >!< server_name) audit(AUDIT_WRONG_WEB_SERVER, "IIS", port);
    if ("Microsoft-IIS/5.0" >!< server_name) audit(AUDIT_NOT_LISTEN, "IIS 5.0", port);
  }
  else
  {
    sig = get_kb_item("www/hmap/" + port + "/description");
    if (!sig) exit(0, "The web server listening on port "+port+" was not fingerprinted.");
    else
    {
      if ("IIS" >!< sig) audit(AUDIT_WRONG_WEB_SERVER, "IIS", port);
      else if ("IIS/5.0" >!< sig) audit(AUDIT_NOT_LISTEN, "IIS 5.0", port);
    }
  }
}

req = 'GET /NULL.printer HTTP/1.1\r\nHost: ' + crap(257) + '\r\n\r\n';
w = http_send_recv_buf(port:port, data:req);

if (w[0] =~ "HTTP/[0-9.]+ 500 13") security_hole(port);
else audit(AUDIT_LISTEN_NOT_VULN, "IIS 5.0", port);
