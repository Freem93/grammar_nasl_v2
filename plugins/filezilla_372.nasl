#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69476);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/01 11:02:44 $");

  script_cve_id("CVE-2013-4852");
  script_bugtraq_id(61599);
  script_osvdb_id(95970);

  script_name(english:"FileZilla Client < 3.7.2 SFTP Integer Overflow");
  script_summary(english:"Checks version of FileZilla");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a 
remote integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FileZilla Client on the remote host is a version prior 
to 3.7.2.  As such, it is affected by an integer overflow vulnerability 
that exists in the 'getstring()' function from PuTTY used to handle 
SFTP. This can lead to a heap overflow during the SSH handshake prior 
to authentication, due to improper bounds checking of the length 
parameter received from the SFTP server. An attacker could exploit this 
issue by tricking a user into connecting to a specially crafted SFTP 
server. This could lead to a denial of service, and potentially code 
execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.search-lab.hu/advisories/secadv-20130722");
  script_set_attribute(attribute:"see_also", value:"https://filezilla-project.org/");
  script_set_attribute(attribute:"solution", value:"Upgrade to FileZilla Client 3.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:filezilla:filezilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

fix = "3.7.2";
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
    security_warning(port:port, extra:report);
  else
    security_warning(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname);

