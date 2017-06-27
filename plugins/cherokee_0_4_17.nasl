#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15617);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2004-1097");
 script_bugtraq_id(11574);
 script_xref(name:"OSVDB", value:"11321");
 script_name(english:"Cherokee Web Server auth_pam Authentication Format String");
 script_summary(english:"Checks for version of Cherokee");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has a format string vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to a format string
attack when processing authentication requests using auth_pam.  This
could allow a remote attacker to cause a denial of service, or
potentially execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://bugs.gentoo.org/show_bug.cgi?id=67667"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Cherokee 0.4.17.1 or later."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/15");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([0-3]\.|4\.([0-9]|1[0-7]))[^0-9.]", string:serv))
 {
   security_hole(port);
 }
