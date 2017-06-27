#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21015);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-0949");
  script_bugtraq_id(16934);
  script_osvdb_id(23616);

  script_name(english:"RaidenHTTPD Crafted Request Script Source Disclosure");
  script_summary(english:"Checks version of RaidenHTTPD");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server suffers from an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RaidenHTTPD, a web server for Windows. 

According to its banner, the version of RaidenHTTPD installed on the
remote Windows host fails to properly validate filename extensions in
URLs.  A remote attacker may be able to leverage this issue to
disclose the source of scripts hosted by the affected application
using specially crafted requests with dot, space, and slash
characters." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-15/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://forum.raidenftpd.com/showflat.php?Cat=&Board=httpd&Number=47234" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RaidenHTTPD version 1.1.48 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/03");
 script_cvs_date("$Date: 2011/09/02 14:48:22 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: RaidenHTTPD/1\.(0\.|1\.([0-9][^[0-9]|([0-3][0-9]|4[0-7])))", string:banner)
) {
  security_warning(port);
  exit(0);
}
