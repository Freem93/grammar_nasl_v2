#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18563);
 script_version("$Revision: 1.12 $");
 script_bugtraq_id(14059);
 script_osvdb_id(17604);
  
 script_name(english:"K-COLLECT CSV_DB / i_DB csv_db.cgi file Parameter Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running K-COLLECT csv-database, a web application
written in perl. 

The remote version of this software fails to sanitize user input to
the 'file' parameter of the 'csv_db.cgi' script before using it to run
a shell command.  An unauthenticated can exploit this issue to execute
arbitrary commands on the remote host subject to the privileges under
which the web server operates." );
 script_set_attribute(attribute:"solution", value:
"Remove this script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/28");
 script_cvs_date("$Date: 2011/03/15 19:22:14 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for K-COLLECT CSV-DB remote command execution flaw");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			check_request:"/csv_db.cgi?file=|id|",
			extra_check:"www\.k-collect\.net/ target=_top>csv-Database Ver.* by K-COLLECT</a></div>",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
