#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21565);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-2403");
  script_bugtraq_id(17972);
  script_osvdb_id(29970);

  script_name(english:"FileZilla FTP Client Unspecified Overflow");
  script_summary(english:"Checks version of FileZilla client"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application is that affected by a 
remote buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version, the FileZilla FTP client installed on the
remote host is affected by an unspecified buffer overflow
vulnerability.  It may be possible to exploit this issue remotely by
tricking a user into connecting to a malicious FTP site using the
affected client. Remote code execution would then be possible subject
to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/projects/filezilla/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FileZilla client version 2.2.23 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/16");
 script_cvs_date("$Date: 2013/08/27 19:29:19 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:filezilla:filezilla");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

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

fix = "2.2.23";
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

