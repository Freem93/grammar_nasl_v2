#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11101);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-1054");
 script_bugtraq_id(3392);
 script_osvdb_id(1963);

 script_name(english:"phpAdsNew helperfunction.php Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be executed on the remote server." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted
on a third-party server using PHPAdsNew.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the HTTP server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHPAdsNew Beta 6.1 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/10/02");
 script_cvs_date("$Date: 2014/04/23 16:29:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of remotehtmlview.php");
 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 local_var r, buf;
 r = http_send_recv3(method:"GET", item:string(loc, "/remotehtmlview.php?phpAds_path=http://xxxxxxxx"),	port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if(egrep(pattern:".*http://xxxxxxxx/dblib\.php.*", string:buf))
 {
 	security_hole(port);
	exit(0);
 }
}

check(loc:"");
foreach dir (cgi_dirs())
{
check(loc:dir);
}
