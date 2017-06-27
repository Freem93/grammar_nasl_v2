#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65722);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2013-1080");
  script_bugtraq_id(58668);
  script_osvdb_id(91627);

  script_name(english:"Novell ZENworks Control Center File Upload Remote Code Execution");
  script_summary(english:"Checks for interim fix");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Novell ZENworks Control Center has a flaw
with authentication checking on '/zenworks/jsp/index.jsp' that can
allow a remote, unauthenticated attacker to upload arbitrary files and
execute them with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7011812");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-049/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ZENworks 11.2.2 and apply the interim fix, or apply 11.2.3a
Monthly Update 1 for 11.2.3 installs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell ZENworks Configuration Management 11 SP2 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell ZENworks Configuration Management Remote Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_detect.nasl");
  script_require_keys("SMB/Novell/ZENworks/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("bsal.inc");
include("byte_func.inc");
include("zip.inc");
include("obj.inc");

get_kb_item_or_exit("SMB/Novell/ZENworks/Installed");

# Get details of the ZCM install.
path = get_kb_item_or_exit("SMB/Novell/ZENworks/Path");
ver = get_kb_item_or_exit("SMB/Novell/ZENworks/Version");

vuln = FALSE;

# 10.3.x is vuln
# 11.2.x is vuln
if (ver =~ "^10\.3($|\.)"  ||
    ver =~ "^11\.2\.[01]($|\.)")
  vuln = TRUE;

if (ver =~ "^11\.2\.3($|\.)")
{
  # fixed in 11.2.3a MU 1
  if(ver_compare(ver:ver, fix:"11.2.3.24691", strict:FALSE) == -1)
    vuln = TRUE;
}

# check if interim fix has been applied
if (ver =~ "^11\.2\.2($|\.)")
{
  jar_file_raw_path = path;
  if (path[strlen(path)-1] != '\\') jar_file_raw_path += '\\';
  jar_file_raw_path += "share\tomcat\webapps\zenworks\WEB-INF\lib\njwc.jar";
  jar_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1",
                         string:jar_file_raw_path);

  share = hotfix_path2share(path: path);

  # Connect to the appropriate share.
  port    =  kb_smb_transport();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  fh = CreateFile(
    file:jar_file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel();
    exit(1, "Unable to open '" + jar_file_raw_path + "'.");
  }

  res = zip_parse(smb:fh);

  # cleanup
  CloseFile(handle:fh);
  NetUseDel();

  if (isnull(res))
    exit(1, "Error while trying to extract '" + jar_file_raw_path + "'.");

  if (isnull(res["files"]["com/novell/web/util/ValidateDateUtil.class"]["timestamp"]))
    exit(1, "Jar file missing information for 'com/novell/web/util/ValidateDateUtil.class'.");

  timestamp = res["files"]["com/novell/web/util/ValidateDateUtil.class"]["timestamp"];
  # msdos format yyyy-mm-dd hh:mm:ss - we are only interested in date portion
  item = eregmatch(pattern: "^(\d{4})-(\d{2})-(\d{2}) ", string:timestamp);
  if (isnull(item))
    exit(1, "Error parsing timestamp on 'com/novell/web/util/ValidateDateUtil.class'.");

  year = int(item[1]);
  month = int(item[2]);
  day = int(item[3]);

  # patch modified date: 3/5/2013
  # check to see if patch has been applied
  if (
    year < 2013 ||
    (year == 2013 && month < 3) ||
    (year == 2013 && month == 3 && day < 5)
  ) vuln = TRUE;
}

if (ver =~ "^11\.2\.3($|\.)")
  fix = "11.2.3a Monthly Update 1";
else
  fix = "11.2.2 with interim fix";

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(kb_smb_transport());
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Novell ZENworks", ver, path);
