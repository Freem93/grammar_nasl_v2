#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16210);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(11329);
 script_osvdb_id(10530, 10535);

 script_name(english:"PHPLinks Multiple Input Validation Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPLinks, a link manager written in PHP.

The remote version of this software has multiple input validation
vulnerabilities that may allow an attacker to execute arbitrary SQL
statements against the remote host or to execute arbitrary PHP code.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:W/RC:X");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/03");
 script_cvs_date("$Date: 2017/02/07 14:52:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phplinks:phplinks");
 script_end_attributes();

 script_summary(english: "Checks for the presence of PHPLinks");
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 r = http_send_recv3(method: "GET", item: dir + "/index.php?show=http://xxx./nessus", port:port, exit_on_fail:TRUE);
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if ( "http://xxx./nessus.php" >< res &&
      "phpLinks" >< res )
 {
   security_hole(port);
   exit(0);
 }
}
audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
