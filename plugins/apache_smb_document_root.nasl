#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17695);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id("CVE-2007-6514");
  script_bugtraq_id(26939);
  script_osvdb_id(43663);

  script_name(english:"Apache Mixed Platform AddType Directive Information Disclosure");
  script_summary(english:"Checks for Apache");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache server is vulnerable to an information disclosure
attack.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Apache.  When Apache runs on a
Unix host with a document root on a Windows SMB share, remote,
unauthenticated attackers could obtain the unprocessed contents of the
directory.  For example, requesting a PHP file with a trailing
backslash could display the file's source instead of executing it.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d73a3dc7");

  script_set_attribute(attribute:"solution", value:
"Ensure that the document root is not located on a Windows SMB
share.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/19");
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
