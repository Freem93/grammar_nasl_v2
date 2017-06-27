#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77175);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id("CVE-2014-0546");
  script_bugtraq_id(69193);

  script_name(english:"Adobe Reader < 10.1.11 / 11.0.08 Sandbox Bypass (APSB14-19)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Windows host is affected by
a sandbox bypass flaw.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is a version
prior to 10.1.11 / 11.0.08. It is, therefore, affected by a sandbox
bypass flaw which can allow an attacker to run arbitrary code with
escalated privileges on Windows hosts.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/reader/apsb14-19.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 10.1.11 / 11.0.08 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");

info =  '';
info2 = '';
vuln = 0;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) audit(AUDIT_KB_MISSING, "SMB/Acroread/Version");

foreach version (vers)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item('SMB/Acroread/'+version+'/Path');
  if (isnull(path)) path = 'n/a';

  verui = get_kb_item('SMB/Acroread/'+version+'/Version_UI');
  if (isnull(verui)) verui = version;

  if (
    (ver[0] == 10 && ver[1] < 1) ||
    (ver[0] == 10 && ver[1] == 1 && ver[2] < 11) ||
    (ver[0] == 11 && ver[1] == 0 && ver[2] < 8)
  )
  {
    vuln++;
    info += '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 10.1.11 / 11.0.08\n';
  }
  else
    info2 += " and " + verui;
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Adobe Reader are";
    else s = " of Adobe Reader is";

    report =
      '\n' + 'The following vulnerable instance'+s+' installed on the'+
      '\n' + 'remote host :\n'+
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}

if (info2)
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Reader "+info2+" "+be+" installed.");
}
else exit(1, "Unexpected error - 'info2' is empty.");
