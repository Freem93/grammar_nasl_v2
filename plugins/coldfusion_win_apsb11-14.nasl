#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55542);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/23 21:23:02 $");

  script_cve_id("CVE-2011-0629", "CVE-2011-2091");
  script_bugtraq_id(48269, 48271);
  script_osvdb_id(73050, 73051);

  script_name(english:"Adobe ColdFusion Multiple Vulnerabilities (APSB11-14) (credentialed check)");
  script_summary(english:"Checks cfm files for CSRF protection & checks for hotfix file");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote Windows host is
affected by an unspecified cross-site request forgery (XSRF)
vulnerability and a denial of service (DoS) vulnerably. Versions 8,
8.0.1, 9, and 9.0.1 are affected.

A remote attacker can exploit the XSRF vulnerability by tricking a
user into making a malicious request, resulting in administrative
access. The DoS vulnerability can be exploited to impact availability
in an unspecified manner.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-14.html");
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb2.adobe.com/cps/907/cpsid_90784.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfixes referenced in the Adobe advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("coldfusion_win.inc");
include("audit.inc");

global_var name, port, login, pass, domain;

cfm_file = "\CFIDE\administrator\logging\archiveexecute.cfm";


##
# checks whether the given instance has the CSRF-related hotfix applied or not
#
# @anonparam instance  name of the instance to check
# @return    relevant plugin output information if the instance is vulnerable,
#            NULL otherwise
##
function check_csrf()
{
  local_var instance, ver, webroot, cfm, path, share, rc, fh, length, blob, info;
  instance = _FCT_ANON_ARGS[0];
  ver = get_kb_item('SMB/coldfusion/' + instance + '/version');
  webroot = get_kb_item('SMB/coldfusion/' + instance + '/webroot');
  path = webroot + cfm_file;
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  cfm = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1', string:path);
  info = NULL;

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    debug_print('Can\'t connect to '+share+' share.');
    return NULL;
  }

  fh = CreateFile(
    file:cfm,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    length = GetFileSize(handle:fh);
    # this should be well under 32k, but we'll double check anyway
    if (length > 32678) length = 32678;
    blob = ReadFile(handle:fh, offset:0, length:length);
    CloseFile(handle:fh);

   if ('CSRFTOKEN' >!< blob)
   {
     info = '\nWeb root : ' + webroot;

     if (ver == '8.0.0')
       info += '\nMissing update : CFIDE-8.zip';
     else if (ver == '8.0.1')
       info += '\nMissing update : CFIDE-801.zip';
     else if (ver == '9.0.0')
       info += '\nMissing update : CFIDE-9.zip';
     else if (ver == '9.0.1')
       info += '\nMissing update : CFIDE-901.zip';
   }
  }
  else debug_print('Unable to open file: ' + path);

  NetUseDel(close:FALSE);

  return info;
}


#
# script starts here
#

instances = get_kb_list('SMB/coldfusion/instance');
inst_to_check = make_list();

# compile a list of the relevant CF versions installed on the host
foreach instance (instances)
{
  ver = get_kb_item('SMB/coldfusion/' + instance + '/version');
  if (ver == '8.0.0' || ver == '8.0.1' || ver == '9.0.0' || ver == '9.0.1')
    inst_to_check = make_list(inst_to_check, instance);
}

if (max_index(inst_to_check) == 0)
  exit(0, 'None of the relevant versions of CF are installed.');

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

info = NULL;
instance_info = make_list();

foreach instance (inst_to_check)
{
  info = check_csrf(instance);

  if (ver == '8.0.0')
    info += check_jar_hotfix(instance, '00003', 4, make_list('00001', '00002', '70523', '71471', '73122', '1875', '77218', '1878'));
  else if (ver == '8.0.1')
    info += check_jar_hotfix(instance, '00003', 5, make_list('00001', '00002', '71471', '73122', '1875', '77218', '1878'));
  else if (ver == '9.0.0')
    info += check_jar_hotfix(instance, '00003', 2, make_list('00001', '00002'));
  else if (ver == '9.0.1')
    info += check_jar_hotfix(instance, '00002', 2, make_list('00001'));

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

NetUseDel();

if (max_index(instance_info) == 0) exit(0, 'No vulnerable instances were detected.');

if (report_verbosity > 0)
{
  report =
    '\nNessus detected the following unpatched instances :\n' +
    join(instance_info, sep:'\n') + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

