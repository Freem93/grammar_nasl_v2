#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11311);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2014/08/28 01:58:09 $");

 script_cve_id("CVE-2002-0692");
 script_bugtraq_id(5804);
 script_osvdb_id(2306);
 script_xref(name:"MSFT", value:"MS02-053");

 script_name(english:"MS02-053: Microsoft FrontPage Extensions shtml.exe Remote Overflow (uncredentialed check)");
 script_summary(english:"Checks for the presence of shtml.exe");

 script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server may be vulnerable to a
buffer overflow attack.");
 script_set_attribute(attribute:"description", value:
"The remote host has FrontPage Server Extensions (FPSE) installed.

There is a denial of service / buffer overflow condition in the
program 'shtml.exe' which comes with it. However, no public detail has
been given regarding this issue yet, so it's not possible to remotely
determine if you are vulnerable to this flaw or not.

If you are, an attacker may use it to crash your web server (FPSE
2000) or execute arbitrary code (FPSE 2002). Please see the Microsoft
Security Bulletin MS02-053 to determine if you are vulnerable or not.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-053");
 script_set_attribute(attribute:"solution", value:"Refer to the Microsoft Security Bulletin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/03");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:internet_information_server");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "www_fingerprinting_hmap.nasl", "smb_registry_full_access.nasl", "smb_reg_service_pack_W2K.nasl", "smb_reg_service_pack_XP.nasl", "frontpage_chunked_overflow.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

w = http_send_recv3(method:"GET", item:"/_vti_bin/shtml.exe", port:port);
if (isnull(w)) exit(1, "The web server did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);

  if("Smart HTML" >< res){
  w = http_send_recv3(method:"GET", item:"/_vti_bin/shtml.exe/nessus.htm", port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);
  if ("&quot;nessus.htm&quot;" >!< res ) security_hole ( port ) ;
 }


