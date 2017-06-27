#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16387);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2014/05/26 16:30:03 $");

 script_cve_id("CVE-2005-0073");
 script_bugtraq_id(12527);
 script_osvdb_id(13707);

 script_name(english:"Sympa src/queue.c queue Utility Local Overflow");
 script_summary(english:"Checks sympa version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
local privilege escalation vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Sympa on the
remote host contains a boundary error in the queue utility when
processing command line arguments, which can result in a stack-based
buffer overflow. A malicious local user could leverage this issue with
a long listname to gain privileges of the 'sympa' user when the script
is run setuid.");
 script_set_attribute(attribute:"solution", value:"Update to Sympa version 4.1.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sympa:sympa");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("sympa_detect.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
  if (ver =~ "^(2\.|3\.|4\.0|4\.1\.[012]([^0-9]|$))")
  {
    security_warning(port);
    exit(0);
  }
}