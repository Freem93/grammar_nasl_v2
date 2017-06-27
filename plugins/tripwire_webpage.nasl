#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(10743);
  script_version("$Revision: 1.21 $");
  script_osvdb_id(616);
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");


  script_name(english:"Tripwire for Webpages Installation Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is using a product to monitor for changes in its
web pages." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Tripwire for Webpages, a commercial product
to monitor for changes in web pages.  This information may prove useful
to anyone doing reconnaissance before launching an actual attack." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Aug/398" );
 script_set_attribute(attribute:"solution", value:
"Set Apache's 'ServerTokens' directive to 'Prod'." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/08/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for information disclosure vulnerability in Tripwire for Webpages";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Check the banner.
banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^Server: +Apache.+ Intrusion/[0-9]", string:banner)
) {
  security_warning(port);
}
