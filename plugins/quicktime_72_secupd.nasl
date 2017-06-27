#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26916);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2007-4673");
  script_bugtraq_id(25913);
  script_osvdb_id(40434);

  script_name(english:"QuickTime < 7.2 Security Update (Windows)");
  script_summary(english:"Checks version of QuickTime / QuickTime.qts");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that allows remote
code execution.");
  script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Windows host may
allow a remote attacker to execute arbitrary code if he can trick a
user on the affected system into opening a specially crafted QTL file.");
  script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=306560");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2007/Oct/msg00000.html" );
  script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or apply Apple's Security Update for QuickTime 7.2 or
later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(78);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl", "smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/QuickTime/Version", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");


qtver = get_kb_item("SMB/QuickTime/Version");
if (isnull(qtver)) exit(0);

iver = split(qtver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 7 ||
  (iver[0] == 7 && iver[1] < 2)
)
{
  report = string(
    "QuickTime version ", qtver, " is installed on the remote host.\n"
  );
  security_hole(port:kb_smb_transport(), extra:report);
  exit(0);
}
else if (iver[0] == 7 && iver[1] == 2)
{
  path = get_kb_item_or_exit("SMB/QuickTime/Path");

  if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

  # Connect to the appropriate share.
  port    =  kb_smb_transport();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

  # Get the version of QTSystem\QuickTime.qts.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  qts =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\QTSystem\QuickTime.qts", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL,share);
  }

  fh = CreateFile(
    file:qts,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = NULL;
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }
  NetUseDel();

  if (!isnull(ver))
  {
    # There's a problem if it's < 7.2.0.245.
    fix = split("7.2.0.245", sep:'.', keep:FALSE);
    for (i=0; i<max_index(fix); i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "QuickTime version ", qtver, ", with QuickTime.qts version ", version, ", is\n",
          "installed on the remote host.\n"
        );
        security_hole(port:port, extra:report);

        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}
