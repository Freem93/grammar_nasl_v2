#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52014);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2009-1523", "CVE-2009-1524");
  script_bugtraq_id(34800);
  script_osvdb_id(54186, 54187);
  script_xref(name:"VMSA", value:"2010-0012");

  script_name(english:"VMSA-2010-0012 : VMware vCenter Update Manager Fix for Jetty Web Server");
  script_summary(english:"Checks the version of Update Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an update manager installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Update Manager installed on the remote
Windows host is 4.0 earlier than Update 3 or 4.1 earlier than Update 1. 
The installed version is, therefore, potentially affected by multiple
vulnerabilities in the embedded Jetty Web server :

  - A directory traversal vulnerability allows a remote,
    unauthenticated attacker to obtain files from the
    remote host. (CVE-2009-1523)

  - A cross-site scripting vulnerability allows a remote
    attacker to execute arbitrary script code in the user's
    browser. (CVE-2009-1524)");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2011/000122.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vCenter Update Manager 4.0 Update 3 / 4.1 Update 1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_update_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/17");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("vmware_vcenter_update_mgr_installed.nasl", "http_version.nasl");
  script_require_keys("SMB/VMware vCenter Update Manager/Version", "SMB/VMware vCenter Update Manager/Build", "SMB/VMware vCenter Update Manager/Path");
  script_require_ports("Services/www");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = 'VMware vCenter Update Manager';
version = get_kb_item_or_exit("SMB/" + app + "/Version");
build = get_kb_item_or_exit("SMB/" + app + "/Build");
path = get_kb_item_or_exit("SMB/" + app + "/Path");

webservers = get_kb_list("Services/www");
jettyver = NULL;
port = 0;
if (!isnull(webservers))
{
  webservers = make_list(list_uniq(webservers));
  for (i=0; i < max_index(webservers); i++)
  {
    server_header = http_server_header(port:webservers[i]);
    if (!isnull(server_header) && 'Jetty' >< server_header)
    {
      jettyver = server_header - 'Jetty(';
      jettyver = jettyver - ')';
      port = webservers[i];
      break;
    }
  }
}

fix = '';
if (version =~ '^4\\.0\\.' && int(build) < 387643)
{
  # Check the Jetty version just in case
  if (isnull(jettyver) || ver_compare(ver:jettyver, fix:'6.1.6') <= 0)
    fix = '4.0.0 build 387643';
  jettypatched = TRUE;
}
else if (version =~ '^4\\.1\\.' && int(build) < 341095)
{
  if (isnull(jettyver) || ver_compare(ver:jettyver, fix:'6.1.6') <= 0)
    fix = '4.1.0 build 341095';
  jettypatched = TRUE;
}

if (fix)
{
  set_kb_item(name:'www/0'+port+'/XSS', value:TRUE);

  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
if (jettypatched) exit(0, 'The host is not affected because the workaround has been applied.');
audit(AUDIT_INST_PATH_NOT_VULN, app, version + ' build ' + build, path);
