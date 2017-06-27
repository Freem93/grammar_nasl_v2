#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47897);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/29 00:33:21 $");

  script_cve_id("CVE-2009-1524");
  script_bugtraq_id(34800);
  script_osvdb_id(54187);
  script_xref(name:"VMSA", value:"2010-0012");
  script_xref(name:"CERT", value:"402580");
  script_xref(name:"Secunia", value:"40577");

  script_name(english:"VMware vCenter Update Manager XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has a cross-site scripting vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware vCenter Update Manager running on the remote
host has a cross-site scripting vulnerability.  This is due to a bug
in Jetty, the underlying web server.  When Jetty displays a directory
listing, arbitrary text can be inserted into the page.

A remote attacker could exploit this by tricking a user into making a
maliciously crafted request, resulting in the execution of arbitrary
script code.

It is likely this version of Update Manager also has a directory
traversal vulnerability, though Nessus did not check for that issue."
  );
  script_set_attribute(attribute:"see_also", value:"http://jira.codehaus.org/browse/JETTY-1004");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/security/advisories/VMSA-2010-0012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb.vmware.com/kb/1023962"
  );
  script_set_attribute(attribute:"solution", value:"Apply the update referenced in VMware's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_update_manager");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mortbay:jetty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  script_require_keys("www/jetty");
  script_require_ports("Services/www", 9084);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:9084);

banner = get_http_banner(port:port);
if (isnull(banner))
  exit(1, 'Error getting banner from port '+port+'.');
if ('Jetty' >!< banner)
  exit(0, 'The web server on port '+port+' doesn\'t appear to be Jetty.');

xss = "<script>alert('" + SCRIPT_NAME + '-' + unixtime() + "')</script>";
dir = '/vum-fileupload/';
url = dir + ';' + xss;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if ('<TITLE>Directory: '+url+'</TITLE>' >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'The web server on port '+port+' is not affected.');
