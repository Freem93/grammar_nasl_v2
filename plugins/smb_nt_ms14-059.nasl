#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78434);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/06 22:02:43 $");

  script_cve_id("CVE-2014-4075");
  script_bugtraq_id(70352);
  script_osvdb_id(113187);
  script_xref(name:"MSFT", value:"MS14-059");
  script_xref(name:"IAVB", value:"2014-B-0138");

  script_name(english:"MS14-059: Vulnerability in ASP.NET MVC Could Allow Security Feature Bypass (2990942)");
  script_summary(english:"Checks the version of System.Web.MVC.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web framework installed that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ASP.NET MVC (Model View Controller) installed on the
remote host is affected by an unspecified cross-site scripting
vulnerability. A remote unauthenticated attacker could exploit this
flaw to execute arbitrary script code in a user's browser subject to
the privileges of the user running the browser.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS14-059");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for ASP.NET MVC 2, 3, 4, 5 and
5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_model_view_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports("Host/patch_management_checks", 139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS14-059";
kbs = make_list(
  "2992080",
  "2993928",
  "2993937",
  "2993939",
  "2994397"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

path = hotfix_get_systemroot();
share = hotfix_path2share(path:path);

mvcs = make_array();

mvcs["2.0"]["path"] = hotfix_append_path(path:path, value:"assembly\GAC_MSIL\System.Web.Mvc\2.0.0.0__31bf3856ad364e35");
mvcs["2.0"]["fix"] = "2.0.60926.0";
mvcs["2.0"]["kb"] = "2993939";
mvcs["3.0"]["path"] = '';
mvcs["3.0"]["fix"] = "3.0.50813.1";
mvcs["3.0"]["kb"] = "2993937";
mvcs["4.0"]["path"] = '';
mvcs["4.0"]["fix"] = "4.0.40804.0";
mvcs["4.0"]["kb"] = "2993928";
mvcs["5.0"]["path"] = '';
mvcs["5.0"]["fix"] = "5.0.20821.0";
mvcs["5.0"]["kb"] = "2992080";
mvcs["5.1"]["path"] = '';
mvcs["5.1"]["fix"] = "5.1.20821.0";
mvcs["5.1"]["kb"] = "2994397";

check_file = "System.Web.Mvc.dll";

name    =  kb_smb_name();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:name);
hcf_init = TRUE;

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

basedir = hotfix_append_path(path:path, value:"Microsoft.NET\assembly\GAC_MSIL\System.Web.Mvc");
dirpat = ereg_replace(string:basedir, pattern:"^[A-Za-z]:(.*)", replace:"\1\*");
iter = FindFirstFile(pattern:dirpat);
while (!isnull(iter[1]))
{
  dir = iter[1];
  iter = FindNextFile(handle:iter);

  if (dir == "." || dir == "..")
    continue;

  if (dir =~ "^v4\.0_3\.0\.0\.[0-9]+__31bf3856ad364e35$")
    mvcs["3.0"]["path"] = hotfix_append_path(path:basedir, value:dir);
  else if (dir =~ "^v4\.0_4\.0\.0\.[0-9]+__31bf3856ad364e35$")
    mvcs["4.0"]["path"] = hotfix_append_path(path:basedir, value:dir);
  else if (dir =~ "^v4\.0_5\.0\.0\.[0-9]+__31bf3856ad364e35$")
    mvcs["5.0"]["path"] = hotfix_append_path(path:basedir, value:dir);
  else if (dir =~ "^v4\.0_5\.1\.0\.[0-9]+__31bf3856ad364e35$")
    mvcs["5.1"]["path"] = hotfix_append_path(path:basedir, value:dir);
  else continue;
}
NetUseDel(close:FALSE);

foreach ver (keys(mvcs))
{
  if (empty_or_null(mvcs[ver]["path"])) continue;
  old_report = hotfix_get_report();
  if (hotfix_check_fversion(path:mvcs[ver]["path"], file:check_file, version:mvcs[ver]["fix"]) == HCF_OLDER)
  {
    file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:mvcs[ver]["path"], replace:"\1\" + check_file);
    kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
    kb_name = ereg_replace(pattern:"//"+check_file, replace:"/"+check_file, string:kb_name);
    version = get_kb_item(kb_name);

    info =
      '\n  Product           : Microsoft ASP.NET MVC ' + ver +
      '\n  File              : ' + hotfix_append_path(path:mvcs[ver]["path"], value:check_file) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + mvcs[ver]["fix"] + '\n';

    hcf_report = '';
    hotfix_add_report(old_report + info, bulletin:bulletin, kb:mvcs[ver]["kb"]);
    vuln = TRUE;
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  set_kb_item(name:"www/0/XSS", value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
