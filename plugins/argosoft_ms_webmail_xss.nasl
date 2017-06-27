#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20985);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-0978");
  script_bugtraq_id(16834);
  script_osvdb_id(23512);

  script_name(english:"ArGoSoft Mail Server Pro Webmail viewheaders Multiple Field XSS");
  script_summary(english:"Checks version of ArGoSoft Mail Server Pro banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ArGoSoft Mail Server Pro, a messaging
system for Windows. 

According to its banner, the webmail server bundled with the version
of ArGoSoft Mail Server Pro installed on the remote host fails to
properly filter message headers before displaying them as part of a
message to users.  A remote attacker may be able to exploit this issue
to inject arbitrary HTML and script code into a user's browser, to be
executed within the security context of the affected website." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-6/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.argosoft.com/rootpages/MailServer/ChangeList.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft Mail Server Pro version 1.8.8.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/27");
 script_cvs_date("$Date: 2015/01/13 06:57:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Check the banner.
banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^Server: ArGoSoft Mail Server Pro.+ \((0\.|1\.([0-7]\.|8\.([0-7]|8\.[0-5])))", string:banner)
) {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
