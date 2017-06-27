#
# (C) Tenable Network Security, Inc.
#

# Supercedes MS02-010
#
# Thanks to Dave Aitel for the details.

include("compat.inc");

if (description)
{
 script_id(11313);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");

 script_cve_id("CVE-2002-0700", "CVE-2002-0718", "CVE-2002-0719");
 script_bugtraq_id(5421, 5422, 5420);
 script_osvdb_id(4862, 4914, 4915);
 script_xref(name:"MSFT", value:"MS02-041");

 script_name(english:"Microsoft Content Management Server (MCMS) 2001 Multiple Remote Vulnerabilities");
 script_summary(english:"Checks for the presence of MCMS");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be run on the remote hosts.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Content Management Server.

There is a buffer overflow in the Profile Service that could allow an
attacker to execute arbitrary code on this host.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-041");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Content Management Server 2001.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/03");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_keys("Settings/ParanoidReport", "www/ASP");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);
if (http_is_dead(port: port)) exit(0);

if(!is_cgi_installed3(port:port, item:"/NR/System/Access/ManualLoginSubmit.asp")) exit(0);

payload = 'NR_DOMAIN=WinNT%3A%2F%2F0AG4ZA0SR80BCRG&NR_DOMAIN_LIST=WinNT%3A%2F%2F0AG4ZA0SR80BCRG&NR_USER=Administrator&NR_PASSWORD=asdf&submit1=Continue&NEXTURL=%2FNR%2FSystem%2FAccess%2FDefaultGuestLogin.asp';

r = http_send_recv3( port: port, method: 'POST',
    		     item: "/NR/System/Access/ManualLoginSubmit.asp",
		     data: payload,
		     add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );

if (isnull(r) || ! r[0]) { security_hole(port); exit(0); }
if (r[0] =~ "^HTTP/[0-9]\.[0-9] 500 ") security_hole(port);
