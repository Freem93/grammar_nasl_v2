#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22048);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id(
    "CVE-2006-5157", 
    "CVE-2006-5211", 
    "CVE-2006-5212", 
    "CVE-2006-6178", 
    "CVE-2006-6179"
   );
  script_bugtraq_id(20284, 20330, 21442);
  script_osvdb_id(29422, 29461, 29462, 32028, 32029);

  script_name(english:"Trend Micro OfficeScan 7.3 Multiple Vulnerabilities");
  script_summary(english:"Checks for OfficeScan stack overflows");
 
  script_set_attribute(attribute:"synopsis", value:"The remote web server is vulnerable to remote code execution.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Trend Micro OfficeScan Server.

This version of OfficeScan is vulnerable to multiple stack overflows in
CGI programs that could allow a remote attacker to execute code in the
context of the remote server. 

Note that OfficeScan server under Windows runs with SYSTEM privileges,
which means an attacker can gain complete control of the affected host. 

In addition, there is a format string vulnerability in the
'ATXCONSOLE.OCX' ActiveX Control that could allow for remote code
execution via malicious input to the console's Remote Client Install
name search as well as flaws that might allow for removal of the
OfficeScan client or arbitrary files from the remote host.");
  script_set_attribute(attribute:"solution", value:"Trend Micro has released 2 patches for OfficeScan 7.3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  # http://web.archive.org/web/20070813050236/http://esupport.trendmicro.com/support/viewxml.do?ContentID=EN-1031753
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?45da9450");
  # http://web.archive.org/web/20070812151847/http://esupport.trendmicro.com/support/viewxml.do?ContentID=EN-1031702
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?4805fbf2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:officescan");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}


include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:8080, embedded: 1);

res = http_send_recv3(method:"GET", port: port, exit_on_fail: 1,
                      item:"/officescan/console/remoteinstallcgi/cgiRemoteInstall.exe" );
if ("Internal+error+when+cgiRemoteInstall%2Eexe" >!< res[2]) exit(0);

res = http_send_recv3(method:"GET", port: port, exit_on_fail: 1,
                      item:"/officescan/console/remoteinstallcgi/cgiRemoteInstall.exe?domain=nessusnessusnessus&client=nessus&user=nessus&password=nessus&checkonly=true&filebase=test&action=1");
if ("Cannot+connect+to+nessus%2E" >< res[2])
   security_hole(port:port);
