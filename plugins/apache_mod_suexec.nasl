#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(17693);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id("CVE-2007-1741", "CVE-2007-1742", "CVE-2007-1743");
  script_bugtraq_id(23438);
  script_osvdb_id(34872, 38639, 38640);

  script_name(english:"Apache mod_suexec Multiple Privilege Escalation Vulnerabilities");
  script_summary(english:"Checks for Apache");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache server is vulnerable to multiple privilege
escalation attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Apache and is potentially
affected by the following vulnerabilities:

  - Multiple race conditions exist in suexec between the
    validation and usage of directories and files. Under
    certain conditions local users are able to escalate
    privileges and execute arbitrary code through the
    renaming of directories or symlink attacks.
    (CVE-2007-1741)

  - Apache's suexec module only performs partial
    comparisons on paths, which could result in privilege
    escalation. (CVE-2007-1742)

  - Apache's suexec module does not properly verify user
    and group IDs on the command line. When the '/proc'
    filesystem is mounted, a local user can utilize suexec
    to escalate privileges. (CVE-2007-1743)

Note that this plugin only checks for the presence of Apache, and does
not actually check the configuration.");

  script_set_attribute(attribute:"solution", value:
"Disable suexec or disallow users from writing to the document root.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=apache-httpd-dev&m=117511568709063&w=2");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=apache-httpd-dev&m=117511834512138&w=2");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("apache_http_version.nasl");
  script_require_keys("www/apache", "Settings/PCI_DSS");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

port = get_http_port(default:80);

# Make sure this is Apache.
get_kb_item_or_exit("www/"+port+"/apache");

# All versions are vulnerable.
source = get_kb_item_or_exit("www/apache/"+port+"/pristine/source", exit_code:1);
version = get_kb_item_or_exit("www/apache/"+port+"/pristine/version", exit_code:1);

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
