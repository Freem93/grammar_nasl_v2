#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73758);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"Websense Email Security Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks version of OpenSSL DLL file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an email security application installed that is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Websense Email Security installed on the remote Windows
host contains a bundled version of an OpenSSL DLL file. It is,
therefore, affected by an information disclosure vulnerability.

An out-of-bounds read error, known as the 'Heartbleed Bug', exists
related to handling TLS heartbeat extensions that could allow an
attacker to obtain sensitive information such as primary key material,
secondary key material, and other protected content.");
  # http://www.websense.com/content/support/library/ni/shared/security-alerts/openssl-vul-2014.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60cf5c8e");
  # http://www.websense.com/support/article/kbarticle/Hotfix-OpenSSL-for-Websense-Email-Security-7-3-with-HF-6-and-later
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35854217");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Refer to the vendor advisory and apply the necessary patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:websense_email_security");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("websense_email_security_installed.nasl");
  script_require_keys("SMB/Websense Email Security/Path");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

function get_file_list(dir, pattern, max_depth)
{
  local_var retx, file_list, dir_list, r_file_list, r_dir;
  if(max_depth < 0)
    return NULL;

  retx = FindFirstFile(pattern:dir + "\*");
  file_list = make_list();
  dir_list = make_list();

  while(!isnull(retx[1]))
  {
    if(retx[2] & FILE_ATTRIBUTE_DIRECTORY && retx[1] != '.' && retx[1] != '..')
      dir_list = make_list(dir_list, retx[1]);
    else
    {
      if(retx[1] =~ pattern)
        file_list = make_list(file_list, dir + "\" + retx[1]);
    }
    retx = FindNextFile(handle:retx);
  }

  foreach r_dir (dir_list)
  {
    r_file_list = get_file_list(dir:dir + "\" + r_dir, pattern: pattern, max_depth: max_depth - 1);
    if(r_file_list != NULL)
      file_list = make_list(file_list, r_file_list);
  }

  return file_list;
}

path = get_kb_item_or_exit('SMB/Websense Email Security/Path');
version = get_kb_item_or_exit('SMB/Websense Email Security/Version');

# Per vendor :
# Any build number greater than 7.3.1181 is vuln
# No need to check earlier versions for the DLL
if (ver_compare(ver:version, fix:"7.3.1181", strict:FALSE) < 0)
  audit(AUDIT_INST_PATH_NOT_VULN, 'Websense Email Security', version, path);

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

registry_init();

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# Find OpenSSL DLLs under main install path
search_dir = ereg_replace(pattern:'[A-Za-z]:(.*)', replace:'\\1', string:path);
dlls = get_file_list(dir:search_dir, pattern:"^(libeay32|ssleay32)\.dll$", max_depth:3);
info = "";
foreach dll (dlls)
{
  temp_path = (share - '$')+ ":" + dll;
  dll_ver = hotfix_get_pversion(path:temp_path);
  err_res = hotfix_handle_error(
    error_code   : dll_ver['error'],
    file         : temp_path,
    appname      : 'Websense Email Security',
    exit_on_fail : FALSE
  );
  if (err_res) continue;

  dll_version = join(dll_ver['value'], sep:".");

  if (dll_version =~ "^1\.0\.1[a-f]$")
    info +=
      '\n  Path              : ' + temp_path +
      '\n  Installed version : ' + dll_version +
      '\n  Fixed version     : 1.0.1g\n';
}
hotfix_check_fversion_end();

if (info)
{
  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Websense Email Security', version, path);
