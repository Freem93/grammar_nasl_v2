#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63300);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2012-5679", "CVE-2012-5680");
  script_bugtraq_id(56922, 56924);
  script_osvdb_id(88389, 88390);
  script_xref(name:"Secunia", value:"49929");

  script_name(english:"Adobe Camera Raw Plug-In Multiple Vulnerabilities");
  script_summary(english:"Checks version of plug-in");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a software plug-in installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Adobe Camera Raw plug-in installed on the remote
host is affected by the following vulnerabilities :

  - A flaw exists when processing an LZW compressed TIFF
    image that can be exploited to cause a heap-based buffer
    underflow via a specially crafted LZW code within an
    image row strip. (CVE-2012-5679)

  - An integer overflow error exists when allocating memory
    during TIFF image processing that can be exploited to
    cause a heap-based buffer overflow via specially crafted
    image dimensions. (CVE-2012-5680)

These vulnerabilities can be exploited by tricking a user into opening
a specially crafted file and could allow an attacker to execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-31/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-28.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Camera Raw Plug-In 6.7.1 / 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:camera_raw");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc"); # for hotfix_path2share
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'Adobe Camera Raw Plug-In';
report = '';

vuln_files = 0;
plugin_found = FALSE;

cf_dir = hotfix_get_commonfilesdirx86();
if (!cf_dir) cf_dir = hotfix_get_commonfilesdir();
if (isnull(cf_dir) || !cf_dir) exit(1, 'Unable to obtain common program files directory.');

share = hotfix_path2share(path:cf_dir);

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) audit(AUDIT_SOCK_FAIL, port);

#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

dirpat = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\Adobe\Plug-Ins\*", string:cf_dir);

plugin_name = 'Camera Raw.8bi';

# Search all Adobe products installed to see if they have Adobe Camera Raw Plug-In Installed
retx = FindFirstFile(pattern:dirpat);
while (!isnull(retx[1]))
{
  if ((retx[2] & FILE_ATTRIBUTE_DIRECTORY) && retx[1] != '.' && retx[1] != '..' &&
      retx[1] =~ "CS[56]")
  {
    plugins_dir = '\\Adobe\\Plug-Ins\\' + retx[1] + '\\File Formats\\';
    plugin_path = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:cf_dir, replace:"\1" + plugins_dir + plugin_name);
    plugin_path_raw = cf_dir + plugins_dir + plugin_name;

    handle = CreateFile(file:plugin_path, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
    if (!isnull(handle))
    {
      v = GetFileVersion(handle:handle);
      CloseFile(handle:handle);
      if (!isnull(v))
      {
        version = join(sep:'.', v);
        plugin_found = TRUE;

        fix = '';

        if (version =~ "^6(\.|$)" && ver_compare(ver:version, fix:"6.7.1", strict:FALSE) == -1)
          fix = "6.7.1";
        else if (version =~ "^7(\.|$)" && ver_compare(ver:version, fix:"7.3", strict:FALSE) == -1)
          fix = "7.3";

        if (fix != '')
        {
           report += '\n  Path              : ' + plugin_path_raw +
                     '\n  Installed version : ' + version +
                     '\n  Fixed version     : ' + fix + '\n';
           vuln_files++;
           if (!thorough_tests) break;
        }
      }
    }
  }
  retx = FindNextFile(handle:retx);
}

NetUseDel();

if (report == '')
{
  if (plugin_found) audit(AUDIT_INST_VER_NOT_VULN, appname);
  else audit(AUDIT_NOT_INST, appname);
}

if (vuln_files > 1)
  report = '\nThe following vulnerable Adobe plug-ins were found :\n' + report;
else
  report = '\nThe following vulnerable Adobe plug-in was found :\n' + report;

if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole(port);
