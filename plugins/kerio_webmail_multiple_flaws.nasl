#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11763);
 script_version("$Revision: 1.27 $");

 script_cve_id("CVE-2002-1434", "CVE-2003-0487", "CVE-2003-0488");
 script_bugtraq_id(
   5507,
   7966, 
   7967, 
   7968, 
   8230, 
   9975
 );
 script_osvdb_id(
   2159, 
   4953, 
   4954, 
   4955, 
   4956, 
   4958, 
   6296
 );

 script_name(english:"Kerio WebMail < 5.7.7 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running version 5 of the Kerio MailServer.

There are multiple flaws in this interface that could allow
an attacker with a valid webmail account on this host 
to obtain a shell on this host or to perform
a cross-site-scripting attack against this host
with a version prior to 5.6.4.

Versions of MailServer prior to 5.6.5 are also prone to a 
denial of service condition when an incorrect login to the
admin console occurs. This could cause the server to crash.

Versions of MailServer prior to 5.7.7 are prone to a remotely 
exploitable buffer overrun condition. This vulnerability exists in the 
spam filter component. If successfully exploited, this could permit 
remote attackers to execute arbitrary code in the context of the 
MailServer software. This could also cause a denial of service in the 
server.

*** This might be a false positive, as Nessus did not have
*** the proper credentials to determine if the remote Kerio
*** is affected by this flaw." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 5.7.7 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/08/19");

 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
 script_end_attributes();
 
 script_summary(english:"Checks for Kerio MailServer");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

res = get_http_banner(port:port, exit_on_fail: 1);
if (egrep(string:res, pattern:"^Server: Kerio MailServer ([0-4]\.|5\.[0-6]\.|5\.7\.[0-6])") )	
{
 		security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
