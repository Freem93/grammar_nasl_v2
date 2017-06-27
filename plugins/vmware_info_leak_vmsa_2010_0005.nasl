#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45414);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");

  script_cve_id("CVE-2009-2277");
  script_bugtraq_id(39106);
  script_osvdb_id(63512);
  script_xref(name:"VMSA", value:"2010-0005");
  script_xref(name:"Secunia", value:"39171");

  script_name(english:"VMware ESX WebAccess Context Data XSS (VMSA-2010-0005)");
  script_summary(english:"Checks for the patch based on an error message");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application hosted on the remote web server has a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of WebAccess hosted on the remote VMware ESX server has a
cross-site scripting vulnerability.  It is possible to specify which XML
web service to use for a given session by passing a specially crafted
value to the 'view' parameter of '/ui/vmDirect.do'.

A remote attacker could exploit this by tricking a user into requesting
a maliciously crafted URL, causing all SOAP requests (including
cleartext authentication credentials) to be sent to a host that is
controlled by the attacker.

This version of ESX likely has other vulnerabilities, though Nessus has
not checked for those."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2010-002.txt");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Mar/250");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2010-0005.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in the VMware advisory, or disable
WebAccess."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:a:vmware:esx_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_hostd_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/vmware_hostd");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

install = get_install_from_kb(appname:'vmware_hostd', port:port, exit_on_fail:TRUE);
base_url = build_url(qs:install['dir'], port:port);

if ('esx' >!< tolower(install['ver'])) exit(0, 'Only VMware ESX and vCenter are affected.');

# valid request
page = install['dir']+'/ui/vmDirect.do';
qs1 = 'view='+base64(str:'wsUrl='+SCRIPT_NAME+'&vmId='+unixtime())+'_';
url1 = page+'?'+qs1;
res1 = http_send_recv3(method:'GET', item:url1, port:port, exit_on_fail:TRUE);

if (
  '<title>VMware Virtual Infrastructure Web Access</title>' >!< res1[2] ||
  'The requested URL is invalid' >< res1[2]
) exit(0, 'The VMware Web Access install at '+base_url+' is not affected.');

# invalid request (null 'wsUrl')
page = install['dir']+'/ui/vmDirect.do';
qs2 = 'view='+base64(str:'wsUrl=&vmId='+unixtime())+'_';
url2 = page+'?'+qs2;
res2 = http_send_recv3(method:'GET', item:url2, port:port, exit_on_fail:TRUE);

if ('The requested URL is invalid' >< res2[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  security_warning(port);
}
else exit(0, 'The VMware Web Access install at '+base_url+' is not affected.');
