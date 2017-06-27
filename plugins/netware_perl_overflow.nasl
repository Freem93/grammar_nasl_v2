#
# (C) Tenable Network Security, Inc.
#

#
# Vulnerable:
# NetWare 5.1 SP6, NetWare 6
########################

include("compat.inc");

if (description)
{
  script_id(11827);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2014/05/26 01:40:12 $");

  script_cve_id("CVE-2003-0562");
  script_bugtraq_id(8251);
  script_osvdb_id(2310);

  script_name(english:"Novell NetWare Web Server CGI2PERL.NLM PERL Handler Remote Overflow");
  script_summary(english:"Too long URL kills NetWare Perl handler");

  script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to a buffer overflow.");
  script_set_attribute(attribute:"description", value:
"The remote web server crashes when it receives a too long URL for the
Perl handler.

It might be possible to make it execute arbitrary code through this
flaw.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/330120");
  script_set_attribute(attribute:"solution", value:"Upgrade to Netware Web Server Later than version 6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:netware");
  script_end_attributes();

  script_category(ACT_DENIAL);
# All the www_too_long_*.nasl scripts were first declared as
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"Netware");

 script_dependencie("http_version.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www",80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);


if(http_is_dead(port:port))exit(0);

r = http_send_recv3(port: port, method: "GET", item: strcat("/perl/", crap(65535)));

if(http_is_dead(port: port, retry:3))
{
  security_hole(port);
  #set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
