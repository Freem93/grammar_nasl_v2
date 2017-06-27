#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14298);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/05/26 16:30:03 $");

 script_osvdb_id(8690);

 script_name(english:"Sympa wwsympa do_search_list Overflow DoS");
 script_summary(english:"Checks sympa version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is susceptible to a
denial of service attack.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Sympa on the
remote host has a flaw in one of it's scripts (wwsympa.pl) that would
allow a remote attacker to overflow the SYMPA server. Specifically,
within the cgi script wwsympa.pl is a 'do_search_list' function that
fails to perform bounds checking. An attacker, passing a specially
formatted long string to this function, would be able to crash the
remote SYMPA server. At the time of this writing, the attack is only
known to cause a denial of service.");
 script_set_attribute(attribute:"solution", value:"Update to version 4.1.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/21");
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
if(!get_port_state(port))
	exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/sympa"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  # jwl : thru 3.3.5.1 vuln
  if (ver =~ "^([0-2]\.|3\.[0-2]\.|3\.3\.[0-4]|3\.3\.5\.[01]([^0-9]|$))")
  {
    security_warning(port);
    exit(0);
  }
}
