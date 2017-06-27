#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97140);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2016-1000000");
  script_bugtraq_id(94496);
  script_osvdb_id(131964);
  script_xref(name:"TRA", value:"TRA-2016-15");
  script_xref(name:"IAVA", value:"2016-A-0335");

  script_name(english:"Ipswitch WhatsUp Gold < 16.5.0 WrFreeFormText.asp sUniqueID Parameter Blind SQLi (credentialed)");
  script_summary(english:"Checks the version of Ipswitch WhatsUp Gold.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a SQL
injection vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Ipswitch WhatsUp
Gold application installed on the remote host is prior to 16.5.0. It
is, therefore, affected by a SQL injection vulnerability within file
WrFreeFormText.asp due to improper sanitization of user-supplied input
to the 'sUniqueID' parameter and the 'find device' field. An
authenticated, remote attacker can exploit this issue to inject or
manipulate SQL queries in the back-end database, resulting in the
manipulation or disclosure of arbitrary data.

Note that this issue was tested only on version 16.4.1 but is believed
to affect all previous versions.");
  # http://docs.ipswitch.com/NM/63_WhatsUpGoldv165/01_ReleaseNotes/index.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f292cca");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/research/tra-2016-15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch WhatsUp Gold version 16.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:whatsup_gold");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ipswitch_whatsup_gold_installed.nasl");
  script_require_keys("SMB/Ipswitch_WhatsUp_Gold/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/Ipswitch_WhatsUp_Gold/";
appname = 'Ipswitch WhatsUp Gold';

version = get_kb_item_or_exit(kb_base + 'Version_NmConsole');
path = get_kb_item_or_exit(kb_base + 'Path');
ver_ui = get_kb_item_or_exit(kb_base + 'Version_UI');

fix = '16.5.0.0';
fix_ui = '16.5.0';

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  port = get_kb_item('SMB/transport');

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver_ui +
      '\n  Fixed version     : ' + fix_ui +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
