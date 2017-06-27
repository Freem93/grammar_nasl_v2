#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: 20 Mar 2003 03:33:03 -0000
#  From: subj <r2subj3ct@dwclan.org>
#  To: bugtraq@securityfocus.com
#  Subject: SimpleChat


include("compat.inc");


if(description)
{
 script_id(11469);
 script_version ("$Revision: 1.16 $");

 script_bugtraq_id(7168);
 script_osvdb_id(53304);

 script_name(english:"SimpleChat Information Disclosure");
 script_summary(english:"Checks for the presence of data/usr");

 script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to retrieve list of users currently connected to
the remote SimpleChat server by requesting the file 'data/usr'.
An attacker may use this flaw to obtain the IP address of every
user currently connected." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2003/Mar/326"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Add a .htaccess file to prevent access to this file. "
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/25");
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

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

port = get_http_port(default:80, embedded: 0);


foreach dir (cgi_dirs())
{
 url = string(dir, "/data/usr");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(0);

 if (res[0] =~ "^HTTP/1\/[01] 200 ")
 {
  if(egrep(pattern:"[0-9]+:\|:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:\|", string:res[2]))
  {
   if (report_verbosity > 0)
   {
    report = string(
     "\n",
     "The following request can be used to verify the issue :\n",
     "\n",
     "  ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
   }
   else security_warning(port);
   exit(0);
  }
 }
}
