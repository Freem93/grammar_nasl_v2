#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56958);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2011-4404");
  script_bugtraq_id(50723);
  script_osvdb_id(54186);
  script_xref(name:"VMSA", value:"2011-0014");
  script_xref(name:"IAVA", value:"2011-A-0160");
  script_xref(name:"EDB-ID", value:"18138");

  script_name(english:"VMware vCenter Update Manager Directory Traversal (VMSA-2011-0014)");
  script_summary(english:"Attempts a directory traversal");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote web server has a directory traversal
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Jetty web server included with VMware vCenter Update
Manager on the remote host has a directory traversal vulnerability.
This is a variant of the issue previously addressed by VMware advisory
VMSA-2010-0012.

The web server runs as SYSTEM by default.  A remote, unauthenticated
attacker could exploit this to read arbitrary files from the host."
  );
  script_set_attribute(attribute:"see_also", value:"http://dsecrg.com/pages/vul/show.php?id=342");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2011-0014.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to vCenter Update Manager 4.1 Update 2 / 4.0 Update 4 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_update_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 9084);
  script_dependencies("vmware_vcenter_update_mgr_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/vcenter_update_mgr");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9084);
install = get_install_from_kb(appname:'vcenter_update_mgr', port:port, exit_on_fail:TRUE);

dir = install['dir'];
file = "..\..\..\jetty\VERSION.txt";
url = dir + "/vci/downloads/.\" + file;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

match = eregmatch(string:res[2], pattern:'^(jetty-[0-9.]+)');
if (isnull(match)) exit(0, 'The VUM install on port ' + port + ' is not affected.');

if (report_verbosity > 0)
{
  report =
    '\nNessus obtained the web server version :\n' +
    '\n' + match[1] + '\n' +
    '\nThis information was obtained via a directory traversal attack' +
    '\nby making the following request :\n' +
    '\n' + chomp(http_last_sent_request()) + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

