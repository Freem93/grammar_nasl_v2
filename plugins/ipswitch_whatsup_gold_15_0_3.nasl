#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62186);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/01/23 17:35:37 $");

  script_cve_id("CVE-2012-2601", "CVE-2012-4344");
  script_bugtraq_id(54626, 55393);
  script_osvdb_id(84313, 84761);
  script_xref(name:"CERT", value:"777007");
  script_xref(name:"EDB-ID", value:"20035");
  script_xref(name:"Secunia", value:"50002");

  script_name(english:"Ipswitch WhatsUp Gold Multiple Vulnerabilities");
  script_summary(english:"Checks version gathered from credentialed check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote host is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Ipswitch WhatsUp Gold prior to 15.0.3
and, as such, may be affected by the following vulnerabilities :

  - There is a blind SQL injection vulnerability in the 
    'sGroupList' parameter of the 'WrVMwareHostList.asp' 
    script. (CVE-2012-2601)

  - An unspecified cross-site scripting vulnerability
    exists involving the SNMP system name. (CVE-2012-4344)"
  );
  # http://docs.ipswitch.com/NM/79_WhatsUp%20Gold%20v15/01_Release%20Notes/index.htm 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88e2610b");
  script_set_attribute(attribute:"see_also", value:"http://www.whatsupgold.com/blog/2012/07/23/keeping-whatsup-gold-secure/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Ipswitch WhatsUp Gold 15.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-13-122");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:whatsup_gold");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

fix = '15.0.3.461';
fix_ui = '15.0.3';

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);
  set_kb_item(name:'www/0/XSS', value:TRUE);

  port = get_kb_item('SMB/transport');
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver_ui +
      '\n  Fixed version     : ' + fix_ui +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
} 
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
