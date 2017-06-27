#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10807);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/05/09 20:31:00 $");

 script_cve_id("CVE-2000-0759");
 script_bugtraq_id(1531);
 script_osvdb_id(674);

 script_name(english:"Apache Tomcat Nonexistent File Error Message Path Disclosure");
 script_summary(english:"Tests for Tomcat Path Disclosure vulnerability.");

 script_set_attribute(attribute:"synopsis", value:
"The instance of Apache Tomcat running on the remote host is affected
by an information disclosure vulnerability");
 script_set_attribute(attribute:"description", value:
"Tomcat will reveal the physical path of the webroot when asked  for a
nonexistent .jsp file. An unauthenticated, remote attacker can exploit
this via a specially crafted request.

An attacker can use this flaw to gain further knowledge about the
remote filesystem layout.");
 script_set_attribute(attribute:"solution", value:"Upgrade to a later software version.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/11/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/03/26");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/tomcat");
 exit(0);
}

# According to this message:
#   Date:  Thu, 22 Nov 2001 17:32:20 +0800
#   From: "analysist" <analysist@nsfocus.com>
#   To: "bugtraq@securityfocus.com" <bugtraq@securityfocus.com>
#   Subject: Hi
# Jakarta Tomcat also reveals the web server install path if we get:
# /AAA...A.jsp  (223 x A)
# /~../x.jsp

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

res = http_send_recv3(method:"GET", item:string("/:/x.jsp"), port:port, exit_on_fail:TRUE);
 
if("Server: Apache Tomcat/3" >< res[1])
{
  path = ereg_replace(pattern:".*HTTP Status 404 - ([^<]*) .The.*",
		    string:res[2],
		    replace:"\1");
  if(ereg(string:path, pattern:"[A-Z]:\\.*", icase:TRUE))
  {
    security_warning(port);
    exit(0);
  }
}
exit(0, "The web server listening on port "+port+" is not affected.");
