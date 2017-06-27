#
# (C) Tenable Network Security, Inc.
#

# based on work from David Maciejak

include("compat.inc");

if (description)
{
 script_id(14323);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");

 script_cve_id("CVE-2004-1735");
 script_bugtraq_id(10992);
 script_osvdb_id(9081);
 script_xref(name:"Secunia", value:"12339");

 script_name(english:"Sympa New List Creation Description Field XSS");
 script_summary(english:"Checks sympa version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Sympa on the
remote host contains an HTML injection vulnerability that may allow a
user who has the privileges to create a new list to inject HTML tags
in the list description field.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/297");
 script_set_attribute(attribute:"solution", value:"Update to version 4.1.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sympa:sympa");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencies("sympa_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

# Test an install.
install = get_kb_item(string("www/", port, "/sympa"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  if (ver =~ "^(2\.|3\.|4\.0\.|4\.1\.[012]([^0-9]|$))")
  {
    security_note(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
