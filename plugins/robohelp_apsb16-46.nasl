#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95950);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/21 14:34:52 $");

  script_cve_id("CVE-2016-7891");
  script_bugtraq_id(94878);
  script_osvdb_id(148577);
  script_xref(name:"IAVB", value:"2016-B-0188");

  script_name(english:"Adobe RoboHelp Unspecified XSS (APSB16-46)");
  script_summary(english:"Checks for APSB16-46 patches");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe RoboHelp installed on the remote Windows host is
affected by an unspecified cross-site scripting (XSS) vulnerability
due to improper validation of input before returning it to users. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to execute arbitrary script code in a user's browser
session.

Note that Nessus has not checked for the patch to file layout.js in
each of the project folders for the RoboHelp projects on the host.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/robohelp/apsb16-46.html");
  # https://helpx.adobe.com/robohelp/kb/cross-site-scripting-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3823a2ab");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate fix according to the instructions in Adobe
Security Bulletin APSB16-46.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("robohelp_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe RoboHelp");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

# Used for reporting
global_var port = kb_smb_transport();

function robohelp_check_file(file, path)
{
  local_var patch, nopatch, login, domain, pass, share;
  local_var rc, fh, size, text, vuln;

  vuln = FALSE;

  if (file =~ "loadcsh\.js")
  {
    patch = "var _loadTopic";
    nopatch = "function loadTopic(defaultTopicURL)";
  }
  if (file =~ "whutils\.js")
  {
    patch = "if(!isRelativeUrl(urlName))";
    nopatch = "(!IsValidTopicURL(urlName))";
  }

  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

  if (!isnull(fh))
  {
    size = GetFileSize(handle:fh);
    if (size > 0)
    {
      text = ReadFile(handle:fh, length:size, offset:0);
      if ( (patch >!< text) && (nopatch >< text) )
        vuln = TRUE;
    }
    CloseFile(handle:fh);
  }
  NetUseDel();
  return vuln;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");
app = "Adobe RoboHelp";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];
patched = FALSE;
report = NULL;

# RoboHelp 2015.0.4
if (version =~ "^12\.")
{
  exe_path = hotfix_append_path(path:path, value:"RoboHTML\RoboHTML.exe");
  fver = hotfix_get_fversion(path:exe_path);

  hotfix_handle_error(error_code:fver['error'], file:exe_path, appname:app, exit_on_fail:TRUE);
  hotfix_check_fversion_end();

  ver = join(fver['value'], sep:'.');
  fixed_version = '12.0.4.460';

  if (ver_compare(ver:ver, fix:fixed_version) < 0)
  {
    file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1RoboHTML\ResponsiveHelpExt\widgets\common\scripts\loadcsh.js", string:path);

    # Check to see if patch was applied instead of an upgrade to 2015.4
    vuln_install = robohelp_check_file(file : file, path : path);

    if (vuln_install)
    {
      report += '\n  File              : RoboHTML.exe' +
                '\n  Installed version : ' + ver +
                '\n  Fixed version     : ' + fixed_version +
                '\n';
    }
    else
      audit(AUDIT_PATCH_INSTALLED, app, "APSB16-46");
  }
  else
    audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
}
else if (version =~ "^11\.")
{
  files = make_array();
  files["loadcsh.js"]["path"] = "RoboHTML\ResponsiveHelpExt\widgets\common\scripts\";
  files["loadcsh.js"]["patch"] = "rh11.zip";

  files["whutils.js"]["path"] = "RoboHTML\WebHelp5Ext\template_stock\";
  files["whutils.js"]['patch'] = "whutils.zip";

  foreach file (keys(files))
  {
    file_loc = ereg_replace(
      pattern : "^[A-Za-z]:(.*)",
      replace : "\1"+files[file]["path"]+file,
      string  : path
    );

    vuln_install = robohelp_check_file(file : file_loc, path : path);
    if (vuln_install)
    {
      report +=
       '\n  File Checked       : ' + file +
       '\n  Patch Required     : ' + files[file]['patch'] +
       '\n';
    }
  }
}
else if (version =~ "^([0-9]|10)\.")
{
  report +=
    '\n  RoboHelp Version     : ' + version +
    '\n  Fix                  : Refer to Adobe support for patch / upgrade instructions'+
    '\n';
}

if (!isnull(report))
{
  if (version =~ "^11\.")
    myreport = '\n  Patch Instructions : https://helpx.adobe.com/robohelp/kb/cross-site-scripting-vulnerability.html' + report;
  else myreport = report;

  security_report_v4(
    severity : SECURITY_WARNING,
    port     : port,
    extra    : myreport,
    xss      : TRUE
  );
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
