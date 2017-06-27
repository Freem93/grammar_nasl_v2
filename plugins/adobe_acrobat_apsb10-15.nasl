#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47164);
  script_version("$Revision: 1.49 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_name(english:"Adobe Acrobat < 9.3.3 / 8.2.3  Multiple Vulnerabilities (APSB10-15)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_cve_id(
    "CVE-2010-1240",
    "CVE-2010-1285",
    "CVE-2010-1295",
    "CVE-2010-1297",
    "CVE-2010-2168",
    "CVE-2010-2201",
    "CVE-2010-2202",
    "CVE-2010-2204",
    "CVE-2010-2205",
    "CVE-2010-2206",
    "CVE-2010-2207",
    "CVE-2010-2208",
    "CVE-2010-2209",
    "CVE-2010-2210",
    "CVE-2010-2211",
    "CVE-2010-2212"
  );
  script_bugtraq_id(
    39109,
    40586,
    41230,
    41231,
    41232,
    41234,
    41236,
    41237,
    41238,
    41239,
    41240,
    41241,
    41242,
    41243,
    41244,
    41245
  );
  script_osvdb_id(
    63667,
    65141,
    65909,
    65910,
    65911,
    65912,
    65913,
    65915,
    65916,
    65917,
    65918,
    65919,
    65920,
    65921,
    65922,
    65923
  );
  script_xref(name:"Secunia", value:"40034");
  
  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Acrobat on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 9.3.3 / 8.2.3.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A social engineering attack could lead to code 
    execution. (CVE-2010-1240)

  - Handling of an invalid pointer could lead to code 
    execution. (CVE-2010-1285)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-1295)

  - A memory corruption vulnerability could lead to code
    execution. This issue is reportedly being exploited in
    the wild. (CVE-2010-1297)

  - Handling of an invalid pointer could lead to code 
    execution. (CVE-2010-2168)

  - Handling of an invalid pointer could lead to code
    execution. (CVE-2010-2201)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-2202)

  - A denial of service vulnerability could potentially lead
    to code execution. (CVE-2010-2204)

  - It may be possible to execute arbitrary code via 
    uninitialized memory locations. (CVE-2010-2205)

  - An error in array-indexing could lead to code 
    execution. (CVE-2010-2206)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-2207)
  
  - Dereferencing a deleted heap object could lead to code
    execution. (CVE-2010-2208)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-2209)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-2210)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-2211)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2010-2212)");

  script_set_attribute(attribute:'see_also',value:'http://www.adobe.com/support/security/bulletins/apsb10-15.html');
  script_set_attribute(attribute:'solution',value:'Upgrade to Adobe Acrobat 9.3.3 / 8.2.3 or later.');
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-164");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "newfunction" Invalid Pointer Use');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies('adobe_acrobat_installed.nasl');
  script_require_keys('SMB/Acrobat/Version');
  exit(0);
}


include('global_settings.inc');

version = get_kb_item('SMB/Acrobat/Version');
if (isnull(version)) exit(1, "The 'SMB/Acrobat/Version' KB item is missing.");
version_ui = get_kb_item('SMB/Acrobat/Version_UI');

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if ( 
  ver[0]  < 8 ||
  (ver[0] == 8 && ver[1]  < 2) ||
  (ver[0] == 8 && ver[1] == 2  && ver[2] < 3) ||
  (ver[0] == 9 && ver[1]  < 3) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 3)
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item('SMB/Acrobat/Path');
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Product           : Adobe Acrobat'+
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 9.3.3 / 8.2.3\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "The host is not affected since Adobe Acrobat "+version_report+" is installed.");
