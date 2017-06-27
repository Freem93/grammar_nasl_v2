#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65614);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/07/18 21:47:36 $");

  script_cve_id("CVE-2013-0107");
  script_bugtraq_id(57558);
  script_osvdb_id(89702);
  script_xref(name:"CERT", value:"275219");

  script_name(english:"Foxit Advanced PDF Editor 3.x < 3.0.4.0 Security Cookie Stack-based Buffer Overflow");
  script_summary(english:"Checks version of Foxit Advanced PDF Editor");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a buffer
overflow vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of Foxit Advanced PDF Editor is 3.x prior to 3.0.4.0.  As
such, it is affected by a stack-based buffer overflow vulnerability
triggered when a document reconstructs the security cookie. 

An attacker could exploit this issue by tricking a user into opening a
specially crafted document, resulting in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.foxitsoftware.com/support/security_bulletins.php#FPAE-1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Foxit Advanced PDF Editor 3.0.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_advanced_pdf_editor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("foxit_pdf_editor_installed.nasl");
  script_require_keys("SMB/Foxit_pdf_editor/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

kb_base = "SMB/Foxit_pdf_editor/";
path = get_kb_item_or_exit(kb_base + "Path");
ver = get_kb_item_or_exit(kb_base + path + "/Version");
appname = get_kb_item_or_exit(kb_base + path + "/Appname");

fix = '3.0.4.0';
if (ver =~ "^3\." && ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix +
        '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
