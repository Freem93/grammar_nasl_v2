#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  From: "Matthew Murphy" <mattmurphy@kc.rr.com>
#  To: "BugTraq" <bugtraq@securityfocus.com>
#  Subject: BadBlue Remote Administrative Access Vulnerability
#  Date: Sun, 20 Apr 2003 16:28:18 -0500


include("compat.inc");

if(description)
{
 script_id(11554);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2003-0332");
 script_bugtraq_id(7387);
 script_osvdb_id(8614);

 script_name(english:"BadBlue ISAPI Extension .hts Crafted File Extension Request Authentication Bypass");
 script_summary(english:"Get the version of the remote BadBlue server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the BadBlue web server earlier than 2.2.
Such versions are reportedly affected by an authentication bypass
vulnerability. It is possible for an attacker to gain administrative
access using a filename with a .ats extension instead of a .hts
extension." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q2/77" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BadBlue v 2.2 or newer as this reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'BadBlue 2.5 EXT.dll Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/20");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service1.nasl", "http_version.nasl");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);

# Technically speaking, version 2.16 is not vulnerable. However since we could
# not test it, we advise everyone to update to 2.2
vulnerable = egrep(pattern:"^Server: BadBlue/(1\.|2\.[0-1])", string:banner);
if(vulnerable)security_hole(port);


