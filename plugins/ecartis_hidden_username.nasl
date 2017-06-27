#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11505);
 script_bugtraq_id(6971);
 script_osvdb_id(9796);
 script_cve_id("CVE-2003-0162");
 
 script_version ("$Revision: 1.16 $");

 script_name(english:"Ecartis HTML Field Manipulation Arbitrary User Password Reset");
 script_summary(english:"Checks for the presence of lsg2.cgi");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has an arbitrary password
reset vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Ecartis Mailing List Manager web
interface (lsg2.cgi).

According to its version number, there is a vulnerability that allows
an authenticated user to change anyone's password, including the list
administrators.  An authenticated attacker could exploit this to take
control of the mailing list." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/Feb/360"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/Mar/27"
 );
 script_set_attribute(attribute:"solution", value:
"Upgrade to an Ecartis Mailing List Manager snapshot version after
20030227." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/02/27");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
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

foreach dir (list_uniq(make_list("/ecartis", cgi_dirs())))
{
 url = string(dir, "/lsg2.cgi");
 res = http_send_recv3(method:"GET", item:url, port:port);

 if(isnull(res)) exit(0);

 if(egrep(pattern:"Ecartis (0\..*|1\.0\.0)", string:res[2]))
 	{
	security_warning(port);
	exit(0);
	}
}
