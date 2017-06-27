#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66317);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/13 21:07:13 $");

  script_cve_id("CVE-2011-2133");
  script_bugtraq_id(49105);
  script_osvdb_id(74430);
  script_xref(name:"EDB-ID", value:"17653");

  script_name(english:"Adobe RoboHelp / RoboHelp Server DOM-based XSS (APSB11-23)");
  script_summary(english:"Checks if js files are unpatched");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host has a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RoboHelp or RoboHelp Server installed on the remote
host has a cross-site scripting vulnerability. An attacker could
exploit this vulnerability by tricking a user into requesting a
maliciously crafted URL, resulting in arbitrary script code execution.");
  # http://malerisch.net/docs/advisories/adobe_robohelp_dom_cross_site_scripting_xss.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc1ae94e");
  # http://www.security-assessment.com/files/documents/advisory/Adobe_RoboHelp_9_-_DOM_XSS.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adc0be86");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-23.html");
  script_set_attribute(attribute:"see_also", value:"http://www.us-cert.gov/ncas/alerts/ta11-222a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Adobe security bulletin
APSB11-23.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:robohelp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("robohelp_installed.nasl", "robohelp_server_installed.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

global_var name, port, login, pass, domain;

##
# Determines if the given file needs to be patched
#
# A file is determined to be vulnerable/unpatched if it does not
# contain a string known to be in the patched version of the file
#
# @remark this function assumes that the caller has already connected
#         to the file share where 'file' exists
# @anonparam file the file to check, relative to the file share it is on (i.e., no leading drive letter)
# @return TRUE if the file is determined to be present and unpatched,
#         FALSE otherwise
##
function _is_file_unpatched()
{
  local_var file, fh, read_failed, length, contents, bytes_to_read, bytes_read, unpatched;
  file = _FCT_ANON_ARGS[0];
  unpatched = FALSE;

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
    return FALSE;

  read_failed = FALSE;
  length = GetFileSize(handle:fh);
  if (length > 40000) length = 40000;  # sanity check - the files are around 10k
  contents = '';

  while (strlen(contents) < length)
  {
    bytes_to_read = length - strlen(contents);
    if (bytes_to_read > 4096) bytes_to_read = 4096;

    bytes_read = ReadFile(handle:fh, offset:strlen(contents), length:bytes_to_read);
    if (strlen(bytes_read) == 0)
    {
      read_failed = TRUE;
      CloseFile(handle:fh);
    }
    contents += bytes_read;
  }

  CloseFile(handle:fh);

  if (read_failed) return FALSE;

  # verify that this is the correct file by looking for a string that
  # exists in patched and unpatched installs
  if ('WebHelp' >!< contents)
    return FALSE;

  # if the file doesn't contain a string that was added by the patch,
  # it is unpatched
  if ('gIllegalTopicNameChars' >!< contents)
    return TRUE;

  return FALSE;
}

##
# checks if any files used by RoboHelp are unpatched
#
# @anonparam install_dir absolute path of directory where RoboHelp is installed
# @return list of unpatched files. if no files need to be patched, an empty list is returned.
#         if an error occured, NULL is returned.
##
function _check_rh_patch()
{
  local_var install_path, files, share, file, js_path, js_files, js_file, unpatched_files, rc;
  install_path = _FCT_ANON_ARGS[0];
  js_files = _FCT_ANON_ARGS[1];
  share = install_path[0] + '$';
  unpatched_files = make_list();

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    return NULL;
  }

  js_files = make_list(
    "RoboHTML\WebHelp5Ext\template_stock\whutils.js",
    "RoboHTML\WildFireExt\template_stock\whutils.js"
  );

  foreach file (js_files)
  {
    js_path = install_path + file; #includes drive name
    js_file = substr(js_path, 2); # sans drive name

    if (_is_file_unpatched(js_file))
      unpatched_files = make_list(unpatched_files, js_path);
  }

  NetUseDel(close:FALSE);
  return unpatched_files;
}

##
# checks if any files published to RoboHelp Server are unpatched
#
# @anonparam install_dir absolute path of directory where RoboHelp Server is installed
# @return list of unpatched files. if no files need to be patched, an empty list is returned
##
function _check_rhs_patch()
{
  local_var install_dir, project_dir, file, share, unpatched_files, fh, rc;
  install_dir = _FCT_ANON_ARGS[0];
  project_dir = install_dir + "robo\server\general\projects";
  share = install_dir[0] + '$';
  unpatched_files = make_list();

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    return unpatched_files;
  }

  fh = FindFirstFile(pattern:substr(project_dir, 2) + "\*"); # remove the drive letter
  while (! isnull(fh))
  {
    if(fh[2] & FILE_ATTRIBUTE_DIRECTORY && fh[1] != '.' && fh[1] != '..')
    {
      file = project_dir + "\" + fh[1] + "\whutils.js";
      if (_is_file_unpatched(substr(file, 2)))  # remove the drive letter
        unpatched_files = make_list(unpatched_files, file);
    }
    fh = FindNextFile(handle:fh);
  }

  NetUseDel(close:FALSE);

  return unpatched_files;
}

rh_paths = get_kb_list('SMB/Adobe_RoboHelp/*/Path');
rhs_paths = get_kb_list('SMB/Adobe_RoboHelp_Server/Path');
if (isnull(rh_paths) && isnull(rhs_paths))
  audit(AUDIT_NOT_INST, 'Adobe RoboHelp/RoboHelp Server');

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rh_report = NULL;
rhs_report = NULL;
non_vuln_rh = make_list();
non_vuln_rhs = make_list();

foreach path (rh_paths)
{
  files = _check_rh_patch(path);
  if (isnull(files) || max_index(files) == 0)
  {
    non_vuln_rh = make_list(non_vuln_rh, path);
    continue;
  }

  foreach file (files)
  {
    if (isnull(rh_report))
      rh_report = '\nThe following RoboHelp files have not been patched :\n\n';

    rh_report += file + '\n';
  }
}

# there should be at most one RHS path, but a loop will be used just
# in case future versions allow multiple RoboHelp Server installations
foreach path (rhs_paths)
{
  files = _check_rhs_patch(path);
  if (isnull(files) || max_index(files) == 0)
  {
    non_vuln_rhs = make_list(non_vuln_rhs, path);
    continue;
  }

  foreach file (files)
  {
    if (isnull(rhs_report))
      rhs_report = '\nThe following files published to RoboHelp Server have not been patched :\n\n';

    rhs_report += file + '\n';
  }
}

NetUseDel();

if (isnull(rh_report) && isnull(rhs_report))
{
  if (max_index(non_vuln_rh) > 0)
    rh_msg = 'The following RoboHelp installs are not vulnerable: ' + join(non_vuln_rh, sep:', ');
  if (max_index(non_vuln_rhs) > 0)
    rhs_msg = 'The following RoboHelp Server installs are not vulnerable: ' + join(non_vuln_rhs, sep:', ');

  exit(0, rh_msg + rhs_msg);
}

set_kb_item(name:'www/0/XSS', value:TRUE);
port = kb_smb_transport();

if (report_verbosity > 0)
{
  report = rh_report + rhs_report;
  security_warning(port:port, extra:report);
}
else security_warning(port);

if (max_index(non_vuln_rh) > 0)
  rh_msg = 'The following RoboHelp installs are not vulnerable: ' + join(non_vuln_rh, sep:', ');
if (max_index(non_vuln_rhs) > 0)
  rhs_msg = 'The following RoboHelp Server installs are not vulnerable: ' + join(non_vuln_rhs, sep:', ');

exit(0, rh_msg + rhs_msg);
