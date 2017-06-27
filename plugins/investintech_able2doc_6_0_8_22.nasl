#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62621);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/12/28 21:13:29 $");

  script_cve_id("CVE-2011-4221");
  script_bugtraq_id(49923);
  script_osvdb_id(76849);
  script_xref(name:"CERT", value:"275036");
  script_xref(name:"EDB-ID", value:"19393");

  script_name(english:"Investintech Able2Doc < 6.0.8.22 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Able2Doc");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Investintech Able2Doc that is earlier
than 6.0.8.22 and therefore reportedly affected by multiple unspecified
vulnerabilities.  These vulnerabilities may allow an attacker to cause a
denial of service condition or execute arbitrary code on the remote host
by tricking a victim into opening a specially crafted PDF document."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade Able2Doc to version 6.0.8.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:investintech:able2doc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies('investintech_able2doc_installed.nasl');
  script_require_keys('SMB/Investintech_Able2Doc/Installed');
  
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

appname = 'Investintech Able2Doc';
kb_base = "SMB/Investintech_Able2Doc/";
report = '';

num_installed = get_kb_item_or_exit(kb_base + 'NumInstalls');
not_vuln_ver_list = make_list();

for (install_num = 0; install_num < num_installed; install_num++)
{
  path = get_kb_item_or_exit(kb_base + install_num + '/Path');
  ver = get_kb_item_or_exit(kb_base + install_num + '/Version');
  fix = '6.0.8.22';
  
  if (ver_compare(ver:ver, fix:fix) == -1)
  {
    report += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';
  }
  else not_vuln_ver_list = make_list(not_vuln_ver_list, ver);
}

versions_not_vuln = '';
for (i=0; i<max_index(not_vuln_ver_list); i++)
{
  versions_not_vuln += ver;
  if (max_index(not_vuln_ver_list) > 1)
  {
    if (i+2 == max_index(not_vuln_ver_list))
      versions_not_vuln += ' and ';
    else if (max_index(not_vuln_ver_list) != 2)
      versions_not_vuln += ', ';
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:get_kb_item('SMB/transport'), extra:report);
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
} 
else
{
  if (max_index(not_vuln_ver_list) > 1)
    msg = appname + ' versions ' + versions_not_vuln + ' are installed and not affected.';
  else
    msg = appname + ' version ' + versions_not_vuln + ' is installed and not affected.';
  exit(0, msg);
}
