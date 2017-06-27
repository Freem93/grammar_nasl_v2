#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20806);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-4142");
  script_bugtraq_id(15786);
  script_osvdb_id(21547);

  script_name(english:"Lyris ListManager Subscription Form Administrative Command Injection");
  script_summary(english:"Checks for administrative command injection vulnerability in ListManager");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an administrative command injection
flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running ListManager, a web-based
commercial mailing list management application from Lyris. 

According to its banner, the version of ListManager installed on the
remote host does not sufficiently sanitize input to the 'pw' parameter
when processing new subscription requests via the web.  Using a
specially crafted request, an unauthenticated attacker may be able to
leverage this flaw to inject administrative commands into the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e252a917" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Dec/374" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ListManager 8.95 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/09");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Do a banner check.
banner = get_http_banner(port:port);
if (
  banner && 
  (
    # later versions of ListManager.
    egrep(pattern:"ListManagerWeb/([0-7]\.|8\.([0-8]|9[abc]))", string:banner) ||
    # earlier versions (eg, 8.5)
    (
      "Server: Tcl-Webserver" >< banner &&
      'Www-Authenticate: Basic realm="Lyris ListManager' >< banner
    )
  )
) security_hole(port);
