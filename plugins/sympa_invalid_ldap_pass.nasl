#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14299);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2014/05/26 16:30:03 $");

 script_osvdb_id(8689);

 script_name(english:"Sympa wwsympa Invalid LDAP Password Remote DoS");
 script_summary(english:"Checks sympa version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is susceptible to a
denial of service attack.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Sympa on the
remote host contains a flaw in the processing of LDAP passwords. A
successful attack would crash the sympa application.");
 script_set_attribute(attribute:"solution", value:"Update to version 3.4.4.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/17");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sympa:sympa");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("sympa_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/sympa"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  if (ver =~ "^3\.4\.3")
  {
    security_warning(port);
    exit(0);
  }
}
