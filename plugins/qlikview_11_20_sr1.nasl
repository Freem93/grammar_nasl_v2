#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65811);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_bugtraq_id(58463);
  script_osvdb_id(91233);

  script_name(english:"QlikView < 11.20 SR1 qvw File Format Parser Integer Overflow");
  script_summary(english:"Checks version of QlikView");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a remote
integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of QlikView is prior to 11.2 SR1 (11.20.11718).  As such,
it is affected by an integer overflow vulnerability that exists in the
'.qvw' file format parser. 

An attacker could exploit this issue by tricking a user into opening a
specially crafted file, resulting in arbitrary code execution.");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130313-0_QlikView_Desktop_Integer_Overflow_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?170e3559");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Mar/75");
  # http://packetstormsecurity.com/files/120797/QlikView-Desktop-Client-11.00-SR2-Integer-Overflow.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5064c356");
  script_set_attribute(attribute:"solution", value:"Upgrade to QlikView 11.20 SR1 (11.20.11718) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qlik:qlikview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("qlikview_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/qlikview/Installed");
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

appname = "QlikView";
kb_base = "SMB/qlikview/";

path = get_kb_item_or_exit(kb_base + "Path");
ver = get_kb_item_or_exit(kb_base + "Version");

fix = '11.20.11718';
if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
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
