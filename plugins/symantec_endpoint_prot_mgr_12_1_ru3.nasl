#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66927);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2013-1612");
  script_bugtraq_id(60542);
  script_osvdb_id(94421);
  script_xref(name:"EDB-ID", value:"33056");

  script_name(english:"Symantec Endpoint Protection Manager < 12.1 RU3 (SYM13-005) (credentialed check)");
  script_summary(english:"Check SEP version");

  script_set_attribute(attribute:"synopsis", value:
"The endpoint management application installed on the remote Windows
host is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is a version prior to 12.1 RU3. It is, therefore,
potentially affected by a buffer overflow vulnerability in the
'secars.dll' component. By exploiting this flaw, a remote,
unauthenticated attacker could execute arbitrary code on the remote
host subject to the privileges of the user running the affected
application.");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2013&suid=20130618_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a400dff");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Endpoint Protection 12.1 RU3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("SMB/sep_manager/path", "SMB/sep_manager/ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = 'Symantec Endpoint Protection';
port = kb_smb_transport();
path = get_kb_item_or_exit('SMB/sep_manager/path');
display_ver = get_kb_item_or_exit('SMB/sep_manager/ver');
vuln = FALSE;

ver = split(display_ver, sep:'.', keep:FALSE);
if (ver[0] == 12 && ver[1] == 0)
{
  edition = get_kb_item_or_exit('SMB/sep_manager/edition');
  if ('sepsb' >< edition)
  {
    appname += ' Small Business Edition';
    vuln = TRUE;
  }
}
else if (ver[0] == 12 && ver[1] == 1 && ver[2] < 3001)   # 12.1 RU3 (12.1.3001)
  vuln = TRUE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + appname +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : 12.1.3001.165 (12.1 RU3)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'SEP', display_ver, path);

