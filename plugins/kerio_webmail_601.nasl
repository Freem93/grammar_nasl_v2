#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14279);
 script_version ("$Revision: 1.14 $");

 script_bugtraq_id(10936);
 script_osvdb_id(8653);

 script_name(english:"Kerio MailServer < 6.0.1 Embedded HTTP Server Unspecified Issue");
 script_summary(english:"Checks for Kerio MailServer < 6.0.1");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote mail server has an unspecified vulnerability."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The remote host is running a version of Kerio MailServer prior to
6.0.1.  Kerio Mailserver is an SMTP server that ships with an
embedded HTTP server. 

It has been reported that there are multiple remote overflows in
versions of Kerio prior to 6.0.1, although the exact nature of these
overflows is not yet known. 

Note that Nessus determined this vulnerability exists based solely on
the version in the received banner.  If the host is running obfuscated
banners, this may be a false positive."
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://securitytracker.com/alerts/2004/Aug/1010949.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to Kerio MailServer 6.0.1 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2004/08/12"
 );
 script_set_attribute(
  attribute:"patch_publication_date", 
  value:"2004/08/12"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2004/08/16"
 );
 script_cvs_date("$Date: 2014/05/02 01:39:55 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/smtp", 25, "Services/www", 80);
 script_dependencies("http_version.nasl", "smtpserver_detect.nasl");
 exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");
include("misc_func.inc");
include("http.inc");


#
# SMTP hard-coded to 25
#
port = 25;
if(get_port_state(port))
{
	s = get_smtp_banner(port:port);
	# 220 f00dikator Kerio MailServer 6.0.1 ESMTP ready

	if (egrep(string:s, pattern:"^220 .* Kerio MailServer ([0-5]\.[0-9]\.[0-9]|6\.0\.0) ESMTP ready") )
	{
		security_hole(port);
		exit(0);
	}
}


# Now, let's try it via port 80

port = get_http_port(default:80);
r = get_http_banner(port:port);
if ( ! r ) exit(0);
#Server: Kerio MailServer 6.0.1
if (egrep(string:r, pattern:"^Server: Kerio MailServer ([0-5]\.[0-9]\.[0-9]|6\.0\.0)") )
	security_hole(port);
