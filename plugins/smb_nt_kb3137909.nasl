#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88699);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/27 20:45:56 $");

  script_name(english:"KB 3137909: Vulnerabilities in ASP.NET Templates Could Allow Tampering");
  script_summary(english:"Checks the template files for the changes.");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host has ASP.NET templates that are affected by
a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description",value:
"The remote Windows host has a version of Visual Studio installed that
has ASP.NET MVC5 or ASP.NET MVC6 project templates that are affected
by a cross-site request forgery (XSRF) vulnerability. ASP.NET projects
built from these templates will be affected by the XSRF vulnerability.");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/en-us/library/security/3137909");
  # https://visualstudiogallery.msdn.microsoft.com/2f8a7e60-2e6b-4220-b334-26d1e60ec54c
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?04aaa19c");
  # https://visualstudiogallery.msdn.microsoft.com/c94a02e9-f2e9-4bad-a952-a63a967e3935
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?346322b4");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a patch for the Visual Studio 2015 ASP.NET
project templates for MVC5 and MVC6. For Visual Studio 2013, you must
manually update the templates as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

app = "Microsoft Visual Studio";

install = get_single_install(app_name:app);

prod = install['Product'];

if ( prod == "2013" )
  key = "SOFTWARE\Microsoft\VisualStudio\12.0\";
else if ( prod == "2015" )
  key = "SOFTWARE\Microsoft\VisualStudio\14.0\";
else audit(AUDIT_INST_VER_NOT_VULN, app + " " + prod);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
mvc5 = get_registry_value(handle:hklm, item:key + "MVC5\AssemblyDirectory");
mvc6 = get_registry_value(handle:hklm, item:key + "MVC6\AssemblyDirectory");

if ( !mvc5 && !mvc6 )
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, "ASP.NET MVC5 or MVC6");
}

path = get_registry_value(handle:hklm, item:key + "Web\WebTemplates\MVC\InstalledPath");
RegCloseKey(handle:hklm);

if ( !path )
{
  close_registry();
  audit(AUDIT_NOT_INST, "MVC web templates");
}

vuln = TRUE;

# Check the ManageController.cs
file = hotfix_get_file_contents(path:path + "CSharp\1033\Spav5.0\Controllers\ManageController.cs");

hotfix_handle_error(error_code:file['error'],
                    file:path + "CSharp\1033\Spav5.0\Controllers\ManageController.cs",
                    appname:app,
                    exit_on_fail:TRUE);

hotfix_check_fversion_end();

pat = '^\\s+\\[HttpPost\\]\\s+\\[ValidateAntiForgeryToken\\]\\s+public\\s+async\\s+Task<ActionResult>\\s+RemovePhoneNumber';

vuln = preg(string:file['data'], pattern:pat, multiline:TRUE);

if ( !vuln )
{
  report = '\n  Microsoft Visual Studio ' + prod +
           '\n  Path : ' + install['path'];
  if ( mvc6 ) report += '\n  MVC  : ASP.NET MVC 6\n';
  else report += '\n  MVC  : ASP.NET MVC 5\n';

  port = kb_smb_transport();
  security_report_v4(port: port, severity: SECURITY_WARNING, extra: report);
}
else audit(AUDIT_HOST_NOT, "affected");
