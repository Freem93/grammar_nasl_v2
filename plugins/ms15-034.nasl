#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82828);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/14 18:29:52 $");

  script_cve_id("CVE-2015-1635");
  script_bugtraq_id(74013);
  script_osvdb_id(120629);
  script_xref(name:"MSFT", value:"MS15-034");
  script_xref(name:"IAVA", value:"2015-A-0092");

  script_name(english:"MS15-034: Vulnerability in HTTP.sys Could Allow Remote Code Execution (3042553) (uncredentialed check)");
  script_summary(english:"Checks response from HTTP.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a vulnerability in the HTTP
protocol stack.");
  script_set_attribute(attribute:"description", value:
"The version of Windows running on the remote host is affected by a
vulnerability in the HTTP protocol stack (HTTP.sys) due to improperly
parsing crafted HTTP requests. A remote attacker can exploit this to
execute arbitrary code with System privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS15-034");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 2008 R2, 8,
8.1, 2012, and 2012 R2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
                      
  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "http_version.nasl");
  script_require_ports("Services/www",80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Check OS
os = get_kb_item("Host/OS");
if ("Microsoft Windows Server 2008 R2" >!< os  && 
    "Microsoft Windows Server 2012" >!< os &&
    "Microsoft Windows 8" >!< os &&
    "Microsoft Windows 7" >!< os)
      audit(AUDIT_OS_NOT,"Microsoft Windows 7, 2008 R2, 8, 8.1, 2012, or 2012 R2");  

# Check for IIS only   
# WinRM and PowerShell Remoting don't seem to be vulnerable according to
# https://twitter.com/Lee_Holmes/status/588464652708806656
port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ("Microsoft-IIS" >!< banner) 
      exit(0, "The web server listening on port " + port + " does not appear to be Microsoft IIS."); 


r = http_send_recv3(port: port, item: "/", method: "GET", 
                    add_headers: make_array("Range", "bytes=0-18446744073709551615"));

if(isnull(r[0])) audit(AUDIT_RESP_NOT, port);

if (r[0] =~ "^HTTP/[0-9.]+ +(416|302|301|307)")
{
  security_hole(port);
}
else if (r[0] =~ "^HTTP/[0-9.]+ +400")
{
  audit(AUDIT_HOST_NOT, 'affected');
}
else
{
  exit(1, "Unexpected HTTP response status from remote port "+ port+ ": " + r[0]);  
}
