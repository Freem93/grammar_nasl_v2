#
# (C) Tenable Network Security, Inc.
#

# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
 script_id(11659);
 script_cve_id("CVE-2002-1004", "CVE-2002-1005", "CVE-2002-1893");
 script_bugtraq_id(5144, 5395, 5906, 7608, 7610);
 script_osvdb_id(5032, 7337, 7338);
 script_version("$Revision: 1.17 $");
 
 script_name(english:"ArGoSoft Mail Server Multiple Remote Vulnerabilities (XSS, DoS, Traversal)");
 script_summary(english:"Gets the version of the remote ArGoSoft server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a mail server that is affected by multiple
remote vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ArGoSoft WebMail interface. The version
found on the remote host is reportedly affected by multiple remote
vulnerabilities :

  - A directory traversal vulnerability could allow remote
    users access to all files on the host.

  - A denial of service vulnerability exists which could
    allow remote attackers with regular user privileges to
    create a mail-loop condition that will consume all
    system resources.

  - A HTML injection vulnerability caused by a failure to
    properly sanitize HTML from email messages.

  - An authentication bypass vulnerability due to the
    free-ware version of ArGoSoft failing to carry out
    sufficient authentication before granting access to the
    user management interface.

  - A denial of service vulnerability in the free-ware
    version. An attacker can exploit this by attempting to
    create a new user using a name of excessive length.

*** Nessus solely relied on the banner of this service to issue
*** this alert." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Oct/89" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Aug/82" );
 script_set_attribute(attribute:"see_also", value:"http://www.argosoft.com/rootpages/MailServer/ChangeList.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrading to ArGoSoft 1.8.3.5 or newer reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/07/04");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

 res = http_get_cache(item:"/", port:port);
 if( res == NULL ) exit(0);
 if((vers = egrep(pattern:".*ArGoSoft Mail Server.*Version", string:res)))
 {
  if(ereg(pattern:".*Version.*\((0\.|1\.([0-7]\.|8\.([0-2]\.|3\.[0-4])))\)", 
  	  string:vers))security_hole(port);
 }

