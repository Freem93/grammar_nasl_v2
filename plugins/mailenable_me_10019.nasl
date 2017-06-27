#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23755);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2006-6239");
  script_bugtraq_id(21325);
  script_osvdb_id(30694);

  script_name(english:"MailEnable NetWebAdmin Unauthorized Access (ME-10019)");
  script_summary(english:"Checks version of MailEnable's NETWebAdmin.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that allows unauthorized
access.");
  script_set_attribute(attribute:"description", value:
"The remote version of MailEnable contains a web-based administration
tool that allows a user to login with a blank password.");
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/");
  script_set_attribute(attribute:"solution", value:"Apply Hotfix ME-10019.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
  script_dependencies("mailenable_detect.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/MailEnable/Installed", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/MailEnable/Installed")) exit(0);
if (get_kb_item("SMB/MailEnable/Standard")) prod = "Standard";
if (get_kb_item("SMB/MailEnable/Professional")) prod = "Professional";
else if (get_kb_item("SMB/MailEnable/Enterprise")) prod = "Enterprise";


# Make sure we're looking at Professional / Enterprise 2.32, which is
# the only version affected according to NetWebAdmin-ReadMe.txt.
if (prod == "Professional" || prod == "Enterprise")
{
  ver = get_kb_item("SMB/MailEnable/"+prod+"/Version");
  path = get_kb_item("SMB/MailEnable/"+prod+"/Path");
  if (!isnull(ver) && !isnull(path) && ver == "2.32")
  {
    # Connect to the appropriate share.
    if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
    port    =  kb_smb_transport();
    login   =  kb_smb_login();
    pass    =  kb_smb_password();
    domain  =  kb_smb_domain();

    if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
    dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\NETWebAdmin\bin\NETWebAdmin.dll", string:path);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      audit(AUDIT_SHARE_FAIL,share);
    }

    fh = CreateFile(
      file:dll,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver2 = GetFileVersion(handle:fh);
      CloseFile(handle:fh);

      # Check the version.
      if (!isnull(ver2))
      {
        fix = split("1.0.2505.31553", sep:'.', keep:FALSE);
        for (i=0; i<4; i++)
          fix[i] = int(fix[i]);

        for (i=0; i<max_index(ver2); i++)
          if ((ver2[i] < fix[i]))
          {
            security_hole(port);
            break;
          }
          else if (ver2[i] > fix[i])
            break;
      }
    }

    # Clean up.
    NetUseDel();
  }
}
