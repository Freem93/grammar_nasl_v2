#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15710);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2014/05/25 02:11:20 $");

 script_cve_id("CVE-2004-0983");
 script_bugtraq_id(11618);
 script_osvdb_id(11534);
 script_xref(name:"DSA", value:"586");
 script_xref(name:"GLSA", value:"200612-21");
 script_xref(name:"RHSA", value:"2004:635");

 script_name(english:"Ruby cgi.rb Malformed HTTP Request CPU Utilization DoS");
 script_summary(english:"Checks for the presence of cgi.rb");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"The 'cgi.rb' CGI is installed. Some versions is vulnerable to remote
denial of service.

By sending a specially crafted HTTP POST request, a malicious user can
force the remote host to consume a large amount of CPU resources.

*** Warning : Nessus solely relied on the presence of this *** CGI, it
did not determine if you specific version is *** vulnerable to that
problem.");
 script_set_attribute(attribute:"see_also", value:"http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:128");
 script_set_attribute(attribute:"see_also", value:"http://www.novell.com/linux/security/advisories/2005_04_sr.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-394-1" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Ruby 1.8.1 or later");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/13");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"cgi.rb", port:port);
if(res)security_warning(port);
