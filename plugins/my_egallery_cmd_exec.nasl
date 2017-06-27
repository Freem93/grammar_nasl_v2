#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# From: "Bojan Zdrnja" <Bojan.Zdrnja@LSS.hr>
# To: <bugtraq@securityfocus.com>
# Subject: Remote execution in My_eGallery
# Date: Thu, 27 Nov 2003 09:37:36 +1300
#

include("compat.inc");

if(description)
{
 script_id(11931);
 script_version ("$Revision: 1.19 $");
 script_bugtraq_id(9113);
 script_osvdb_id(2867);

 script_name(english:"My_eGallery < 3.1.1g Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
a remote file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting the 'my_egallery' PostNuke module. The
installed version is potentially affected by a remote file include 
vulnerability because the application fails to properly sanitize input
to include include statements.

An attacker may use this flaw to execute arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 # http://web.archive.org/web/20070519015355/http://packetstormsecurity.nl/0311-exploits/myegallery.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?116ab6d1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to My_eGallery 3.1.1g or later as this reportedly fixes the
issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/11/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/26");
 script_cvs_date("$Date: 2013/12/23 22:44:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the version of My_eGallery";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
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

if(!can_host_php(port:port)) exit(0);

foreach dir (cgi_dirs())
{
 w = http_send_recv3(method:"GET", item:dir + "/modules.php?name=My_eGallery", port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 if (egrep(pattern:"Powered by: My_eGallery ([0-2]\.|3\.0\.|3\.1\.0|3\.1\.1\.?[a-f])", string:res)) { security_hole(port); exit(0); }
}
