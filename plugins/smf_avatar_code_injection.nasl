#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19550);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2005-2817");
  script_bugtraq_id(14706);
  script_osvdb_id(19120);

  script_name(english:"Simple Machines Forum Avatar Information Disclosure Vulnerability");
  script_summary(english:"Checks for avatar code execution vulnerability in Simple Machines Forum");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows for the
disclosure of information.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Simple Machines Forum (SMF), an open source
web forum application written in PHP.

The installed version of SMF on the remote host does not properly
sanitize the URI supplied for the user avatar.  An attacker who is
registered in the affected application can exploit this flaw to run
scripts each time a forum user accesses the malicious avatar, eg
collecting forum usage information, launching attacks against users'
systems, etc.");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/smf105.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/438");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("smf_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'simple_machines_forum', port:port, exit_on_fail:TRUE);

url = install['dir'] + '/';

version = install['ver'];
ver = split(sep:'.', ver);

for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 1 && ver[1] == 0 && ver[2] <= 5)
{
  if (report_verbosity > 0)
  {
   report =
      '\n  URL     : ' + url +
      '\n  Version : ' + version + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
