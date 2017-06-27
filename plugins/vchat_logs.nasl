#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: 23 Mar 2003 02:24:23 -0000
#  From: subj <r2subj3ct@dwclan.org>
#  To: bugtraq@securityfocus.com
#  Subject: VChat


include("compat.inc");

if(description)
{
 script_id(11471);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2011/03/14 21:48:14 $");
 script_bugtraq_id(7186, 7188);
 script_osvdb_id(53386, 53387);

 script_name(english:"VChat Multiple Remote Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"It is possible to retrieve the log of all the chat sessions
that have occurred on the remote vchat server by requesting
the file vchat/msg.txt

An attacker may use this flaw to read past chat sessions and
possibly harass its participants.

In addition to this, another flaw in the same product may 
allow an attacker to consume all the resources of the remote 
host by sending a long message to this module." );
 script_set_attribute(attribute:"solution", value:
"None at this time. Add a .htaccess file to prevent an 
attacker from obtaining this file." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/25");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of vchat/msg.txt");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
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
  res = http_send_recv3(method:"GET", item:string(dir, "/msg.txt"), port:port,
      exit_on_fail: TRUE);

  if(egrep(pattern:"HTTP/.\.. 200 ", string:res[0]))
  {
    if(egrep(pattern:"^<b>.* :</b>.*<br>$", string:res[2]))
    {
     security_warning(port);
     exit(0);
  }
 }
}
