#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10591);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2014/05/26 15:30:09 $");

 script_cve_id("CVE-2000-0940");
 script_bugtraq_id(1864);
 script_osvdb_id(488);

 script_name(english:"Metertek pagelog.cgi Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of /cgi-bin/pagelog.cgi");

 script_set_attribute(attribute:"synopsis", value:"It may be possible to create arbitrary files on the remote system.");
 script_set_attribute(attribute:"description", value:
"The 'pagelog.cgi' cgi is installed. This CGI has a well known security
flaw that lets an attacker create arbitrary files on the remote
server, ending in .txt, and reading arbitrary files ending in .txt or
.log

*** Warning : this flaw was not tested by Nessus. Check the existence
of /tmp/nessus_pagelog_cgi.txt on this host to find out if you are
vulnerable or not.");
 script_set_attribute(attribute:"solution", value:"Remove it from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/01/08");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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

flag = 0;

foreach dir (cgi_dirs())
{
 if(is_cgi_installed3(item:string(dir, "/pagelog.cgi"), port:port))
 {
  flag = 1;
  directory = dir;
  break;
 }
}

if(flag)
{
  # We create a file but cannot check its existence
  r = http_send_recv3(method:"GET", port:port,
    item:string(directory,
  "/pagelog.cgi?name=../../../../../../tmp/nessus_pagelog_cgi") );
  security_warning(port);
}
