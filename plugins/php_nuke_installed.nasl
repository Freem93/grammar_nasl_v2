#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11236);
 script_version ("$Revision: 1.35 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

 script_cve_id(
  "CVE-2001-0292",
  "CVE-2001-0320",
  "CVE-2001-0854",
  "CVE-2001-0911",
  "CVE-2001-1025",
  "CVE-2002-0206",
  "CVE-2002-0483",
  "CVE-2002-1242",
  "CVE-2003-1400",
  "CVE-2003-1435"
 );
 script_bugtraq_id(
  6446,
  6465,
  6503,
  6750,
  6887,
  6890,
  7031,
  7060,
  7078,
  7079
 );
 script_osvdb_id(
  5513,
  6237,
  6238,
  6239,
  6240,
  6241,
  6242,
  6243,
  6244,
  53993,
  53994
 );

 script_name(english:"PHP-Nuke Detection");
 script_summary(english:"Determines if PHP-Nuke is installed on the remote host");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application might be affected by several vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a copy of PHP-Nuke.

Given the insecurity history of this package, the Nessus team
recommends that you do not use it but use something else instead, as
security was clearly not in the mind of the persons who wrote it. 

The author of PHP-Nuke (Francisco Burzi) even started to rewrite the
program from scratch, given the huge number of vulnerabilities");
 script_set_attribute(attribute:"see_also", value:"http://www.phpnuke.org/modules.php?name=News&file=article&sid=5640");
 script_set_attribute(attribute:"solution", value:
"De-install this package and use something else.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79, 89);

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/17");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phpnuke:php-nuke");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080, php: 1);

function check(loc)
{
 local_var r;

 loc += '/';
 r = http_send_recv3(method:"GET", item:string(loc), port:port, follow_redirect: 2, exit_on_fail: TRUE);
 if("PHP-Nuke" ><r[2] &&
    egrep(pattern:"GENERATOR.*PHP-Nuke.*", string:r[2]))
	{
	if ( ! loc ) loc = "/";
	set_kb_item(name:"www/" + port + "/php-nuke", value:"unknown under " + loc);
	set_kb_item(name:"www/php-nuke", value: TRUE);
	return(1);
	}
 else 
	return(0);
}

 
foreach dir (cgi_dirs())
{
if(check(loc:string(dir))){ security_hole(port); exit(0); }
}

exit(0, "PHP-Nuke was not found on the web server on port "+port+".");
