#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25039);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-2318");
  script_bugtraq_id(23506);
  script_osvdb_id(34436, 34437);

  script_name(english:"FileZilla FTP Client < 2.2.32 Multiple Format Strings");
  script_summary(english:"Checks version of FileZilla client"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple format string vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version, the FileZilla FTP client installed on the
remote host is affected by multiple format string vulnerabilities. 
Details on the issues are not currently available, but it is expected
that exploitation would require a user visit a malicious FTP site
using the affected software." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/projects/filezilla/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FileZilla client version 2.2.32 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/16");
 script_cvs_date("$Date: 2016/05/05 16:01:14 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:filezilla:filezilla");
 script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("filezilla_client_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/filezilla/Installed");
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

appname = "FileZilla Client";
kb_base = "SMB/filezilla/";
port = kb_smb_transport();

fix = "2.2.32";
fixnum = fix;
report = "";
installs = get_kb_item_or_exit(kb_base + "installs");
for (i = 0; i < installs; i++)
{
  path = get_kb_item_or_exit(kb_base + "install/" + i + "/Path");
  ver = get_kb_item_or_exit(kb_base + "install/" + i + "/Version");
  vernum = get_kb_item_or_exit(kb_base + "install/" + i + "/VersionNumber");

  if (ver_compare(ver:vernum, fix:fixnum, strict:FALSE) == -1)
  {
    if (report_verbosity > 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
}

if (report != "")
{
  if (report_verbosity > 0)
    security_hole(port:port, extra:report);
  else
    security_hole(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname);

