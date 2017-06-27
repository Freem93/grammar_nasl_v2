#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90712);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_cve_id("CVE-2016-1035");
  script_osvdb_id(136945);
  script_xref(name:"IAVB", value:"2016-B-0076");

  script_name(english:"Adobe RoboHelp Server Unspecified SQLi (APSB16-12)");
  script_summary(english:"Checks for patched files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by an unspecified SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"Adobe RoboHelp Server version 9 is installed on the remote host, and
it is missing a hotfix that resolves Adobe security advisory
APSB16-12. It is, therefore, affected by an unspecified SQL injection
vulnerability due to improper sanitization of user-supplied input
before using it in SQL queries. An unauthenticated, remote attacker
can exploit this to inject or manipulate SQL queries on the back-end
database, resulting in the disclosure of arbitrary data.

Note that Nessus has not attempted to exploit this issue but has
instead checked to verify that the vendor-supplied patch has been
applied.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/robohelp-server/apsb16-12.html");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("robohelp_server_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe RoboHelp Server");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = "Adobe RoboHelp Server";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

if (version !~ "^9($|\.)")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

# Determine the version of Robo.dll.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
file1 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1WEB-INF\Resources\en_US\ReportResources.xml", string:path);
file2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1WEB-INF\classes\adobe\robohelp\server\WebAdminGroup.class", string:path);
file3 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1WEB-INF\classes\adobe\robohelp\server\FlexReports\Report.class", string:path);

files = make_list(file1, file2, file3);
vuln = FALSE;

foreach file (files)
{
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    debug_print("Failed to connect to the '"+share+".");
    continue;
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
      blob = ReadFile(handle:fh, length:size, offset:0);
      if ("ReportResources.xml" >< file)
      {
        if ('value="Selected area(s) is/are invalid. Please use a valid area on the server"' >!< blob) vuln = TRUE;
      }
      else
      {
        md5 = hexstr(MD5(blob));
        if (
          "WebAdminGroup.class" >< file &&
          md5 == "4340ad5684e6311a6d212dc773838cb4"
        )  vuln = TRUE;
        if (
          "Report.class" >< file &&
          md5 == "e9c20634cf6ffc25657c8e8f91edee11"
        ) vuln = TRUE;
      }
    }
  }
  CloseFile(handle:fh);
  if (vuln) break;
}
NetUseDel();

# Report if an issue was found.
if (vuln)
{
  report =
    '\nNessus was able to verify this issue by examining the host for'+
    '\nthe missing patch. This was verified by using the following file :' +
    '\n' +
    '\n' + file + '\n';
  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, sqli:TRUE);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
