#
# (C) Tenable Network Security, Inc.
#

# Date: Thu, 9 Jan 2003 00:50:48 +0200 (EET)
# From: Jouko Pynnonen <jouko@solutions.fi>
# To: <vulnwatch@vulnwatch.org>
# Subject: [VulnWatch] IMP 2.x SQL injection vulnerabilities


include("compat.inc");

if (description)
{
 script_id(11488);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2013/05/28 17:31:51 $");

 script_cve_id("CVE-2003-0025");
 script_bugtraq_id(6559);
 script_osvdb_id(10105);

 script_name(english:"Horde IMP mailbox.php3 Multiple Parameter SQL Injection");
 script_summary(english:"Checks IMP version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple sql injection vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote server is running IMP, a web-based mail client.  There is a
bug in the installed version which allows an attacker to perform a SQL
injection attack using the 'actionID' parameter of the 'mailbox.php3'
script.

An attacker may use this flaw to gain unauthorized access to a user
mailbox or to take the control of the remote database.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=104204786206563&w=2");
 script_set_attribute(attribute:"solution", value:
"IMP 2.x is deprecated. Update to IMP 3.x or 4.x.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/27");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/08");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:imp");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1);


dirs = make_list(cgi_dirs(), "/imp", "/horde/imp");
foreach d (dirs)
{
  u = strcat(d, "/mailbox.php3?actionID=6&server=x&imapuser=x';somesql&pass=x");
  res = http_send_recv3(method:"GET", item: u, port:port, exit_on_fail: 1);

  if('parse error at or near "somesql"' >< res[2])
  {
    if (report_verbosity < 1)
      security_hole(port:port);
    else
      security_hole(port: port, extra:
'\nThe following URL will expose the flaw !:\n\n' +
  build_url(port: port, qs: u));
   set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
   exit(0);
  }
}
exit(0, "No vulnerable CGI was found on port "+port+".");
