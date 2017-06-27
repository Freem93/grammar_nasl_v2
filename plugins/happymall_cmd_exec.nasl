#
# (C) Tenable Network Security, Inc.
#

# Ref: http://seclists.org/vulnwatch/2003/q2/60


include("compat.inc");

if(description)
{
 script_id(11602);
 script_version ("$Revision: 1.21 $");

 script_cve_id("CVE-2003-0243");
 script_bugtraq_id(7529, 7530);
 script_osvdb_id(3566, 3602);
 
 script_name(english:"HappyMall Multiple Script Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running the HappyMall E-Commerce CGI suite." );
 script_set_attribute(attribute:"description", value:
"There is a flaw HappyMall that could allow an attacker to execute
arbitrary commands with the privileges of the HTTP daemon (typically
root or nobody), by making a request like :
	/shop/normal_html.cgi?file=|id|

In addition, member_html.cgi has been reported vulnerable. However,
Nessus has not checked for this." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q2/60" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this CGI" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/03");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for HappyMall");
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
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
			extra_dirs:make_list("/shop"),
			check_request:"/normal_html.cgi?file=|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
