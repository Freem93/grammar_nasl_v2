#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49999);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id("CVE-2010-3243", "CVE-2010-3324");
  script_bugtraq_id(42467, 43703);
  script_osvdb_id(68123, 68548);
  script_xref(name:"MSFT", value:"MS10-072");

  script_name(english:"MS10-072: Vulnerabilities in SafeHTML Could Allow Information Disclosure (2412048) (remote check)");
  script_summary(english:"SharePoint Services anonymous web banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by multiple cross-site scripting
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of SharePoint Services, SharePoint Server installed on
the remote host has multiple cross-site scripting vulnerabilities.

A remote attacker could exploit them by tricking a user into making a
malicious request, resulting in arbitrary script code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-072");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for SharePoint Services 3.0 and
SharePoint Server 2007."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Aug/178");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_services");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl", "sharepoint_detect.nasl");
  script_require_keys("www/ASP", "www/sharepoint");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if ( get_kb_item("SMB/dont_send_in_cleartext") ) exit(0);

port = get_http_port(default:80, asp:TRUE);
sharepoint = get_install_from_kb(appname:'sharepoint', port:port, exit_on_fail:TRUE);

url =  sharepoint['dir'] + "/default.aspx";

res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  username:kb_smb_login(),
  password:kb_smb_password(),
  exit_on_fail:TRUE
);

# When running SharePoint Services 3.0, the HTTP header version does not get updated
# on all ports. We'll only do the version check on the service where it is updated
if ('Home - Central Administration' >!< res[2])
  exit(1, 'Unable to compare version from port '+port);

version = eregmatch(pattern:"MicrosoftSharePointTeamServices: ([0-9\.]+)", string:res[1]);
if (isnull(version))
{
  exit(1, "MicrosoftSharePointTeamServices not found on port " + port + ".");
}

build = eregmatch(pattern:"([0-9]+)\.[0-9]+\.[0-9]+\.([0-9]+)", string:version[1]);
if (isnull(build))
{
  exit(1, "Cannot extract the version from "+ version[1]+" for the SharePoint Server listening on port "+port+".");
}

if (int(build[1]) == 12 && int(build[2]) >= 6421 && int(build[2]) < 6545)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version[1] +
             '\n  Fixed version     : 12.0.0.6545\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  exit(0);
}
else exit(0, 'SharePoint Server v' + version[1] + ' is listening on port ' + port + ' and is not affected.');
