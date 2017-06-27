#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58399);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/05/16 17:31:50 $");

  script_cve_id(
    "CVE-2012-0121", 
    "CVE-2012-0122", 
    "CVE-2012-0123", 
    "CVE-2012-0124"
  );
  script_bugtraq_id(52431);
  script_osvdb_id(80102, 80103, 80104, 80105);
  script_xref(name:"EDB-ID", value:"19484");

  script_name(english:"HP Data Protector Express 5.x < 5.0.0 Build 59287 / 6.x < 6.0.0 Build 11974 Multiple Vulnerabilities");
  script_summary(english:"Checks version of HP Data Protector Express");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a backup application that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Data Protector Express installed on the remote
Windows host is 5.x earlier than 5.0.0 build 59287 or 6.x earlier than
6.0.0 build 11974.  As such, it is potentially affected by multiple
unspecified denial of service and code execution vulnerabilities.");
  
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03229235
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94781a20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Data Protector Express 5.0.0 build 59287 / 6.0.0 build
11974 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Data Protector Create New Folder Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector_express");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  
  script_dependencies("hp_data_protector_exp_installed.nasl");
  script_require_keys("SMB/HP Data Protector Express/Path", "SMB/HP Data Protector Express/Version", "SMB/HP Data Protector Express/Build");
  
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit('SMB/HP Data Protector Express/Path');
version = get_kb_item_or_exit('SMB/HP Data Protector Express/Version');
build = get_kb_item_or_exit('SMB/HP Data Protector Express/Build');

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;
if (ver[0] == 5 && ver[1] == 0 && ver[2] == 0 && ver_compare(ver:build, fix:'59287') == -1)
  fix = '5.0.0 build 59287';
else if (ver[0] == 6 && ver[1] == 0 && ver[2] == 0 && ver_compare(ver:build, fix:'11974') == -1)
  fix = '6.0.0 build 11974';

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, 'The HP Data Protector Express '+version+' build '+build+' install in '+path+' is not affected.');
