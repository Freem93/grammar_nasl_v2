#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14293);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2004-2578");
 script_bugtraq_id(10895);
 script_osvdb_id(8354);

 script_name(english:"phpGroupWare Admin/Setup Password Plaintext Cookie Storage");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of PhpGroupWare installed on the remote host is reported
to be affected by a plaintext cookie authentication credentials
information disclosure vulnerability. If web administration of
PhpGroupWare is not conducted over an encrypted link, an attacker with
the ability to sniff network traffic could easily retrieve these
passwords. This may aid the attacker in further system compromise." );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20040920024328/www.phpgroupware.org/" );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.16.002 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/28");
 script_cvs_date("$Date: 2015/06/23 19:16:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpgroupware:phpgroupware");
script_end_attributes();

 summary["english"] = "Checks for PhpGroupWare version";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.|16\.0*[01]([^0-9]|$)))", string:matches[1]) )
	security_warning(port);
			
