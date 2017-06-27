#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# References:
# Date:  Mon, 11 Mar 2002 12:46:06 +0700
# From: "Fyodor" <fyarochkin@trusecure.com>
# To: bugtraq@securityfocus.com
# Subject: SunSolve CD cgi scripts...
#
# Date: Sat, 16 Jun 2001 23:24:45 +0700
# From: Fyodor <fyodor@relaygroup.com>
# To: security-alert@sun.com
# Subject: SunSolve CD security problems..
#

include("compat.inc");

if (description)
{
  script_id(11066);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2002-0436");
  script_bugtraq_id(4269);
  script_osvdb_id(10598);

  script_name(english:"Sun Sunsolve CD Pack sscd_suncourier.pl email Parameter Arbitrary Command Execution");
  script_summary(english:"SunSolve CD CGI scripts are vulnerable to a few user input validation problems");

  script_set_attribute(attribute:'synopsis', value:
"The remote service is vulnerable to injection attacks allowing command
execution.");
  script_set_attribute(attribute:'description', value:
"The Sunsolve CD is part of the Solaris Media pack. It is included as a
documentation resource, and is available for the Solaris Operating
Environment.

Sunsolve CD CGI scripts does not validate user input. Crackers may use
them to execute some commands on your system.

** Note: Nessus did not try to perform the attack.");
  script_set_attribute(attribute:'see_also', value:"http://seclists.org/bugtraq/2002/Mar/202");
  script_set_attribute(attribute:'solution', value:"Do not use the SunSolve CD.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("find_service1.nasl", "http_version.nasl", "no404.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 8383);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:8383);

if (is_cgi_installed3(port: port, item:"/cd-cgi/sscd_suncourier.pl")) {
	security_hole(port);
	exit(0);
}

if (is_cgi_installed3(port: port, item:"sscd_suncourier.pl")) {
	security_hole(port);
	exit(0);
}
