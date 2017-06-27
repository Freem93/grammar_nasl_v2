#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(31786);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2007-6258");
 script_bugtraq_id(27752);
  script_osvdb_id(43189);
  script_xref(name:"EDB-ID", value:"5330");
 
 script_name(english:"Apache mod_jk2 Host Header Multiple Fields Remote Overflow");
 script_summary(english:"Checks version of mod_jk2");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple buffer overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apache web server with mod_jk2, a connector
that connects a web server such as Apache web server. 

According to its banner, the version of mod_jk2 installed on the
remote host is affected by multiple buffer overflow vulnerabilities. 
An attacker may be able to exploit these vulnerabilities to cause a
denial of service condition or execute arbitrary code subject to the
privileges of the user running the Apache process." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/487983" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bad43ab" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to mod_jk2 2.0.4 or higher." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/04");
 script_cvs_date("$Date: 2012/04/26 02:24:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

if (!get_kb_item("www/apache")) exit(0);

port = get_http_port(default:80);
banner = get_backport_banner(banner:get_http_banner(port:port));
if(!banner || backported )exit(0);

serv = strstr(banner, "Server:");
serv = serv - strstr(serv, '\r\n');
if ("Apache" >!< serv || "mod_jk2" >!< serv) exit(0);

ver = ereg_replace(pattern:".*mod_jk2/([0-9]+\.[^ ]+).*$", replace:"\1", string:serv);
if(ver && ereg(pattern:"^([0-1]\.|2\.0($|\.[0-3]($|[^0-9])))", string:ver))
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "mod_jk2 version ", ver, " appears to be running on the remote host\n",
      "based on the following Server response header :\n",
      "\n",
      "  ", serv, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
