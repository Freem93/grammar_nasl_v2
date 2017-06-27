#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40447);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id('CVE-2009-1862', 'CVE-2009-1863', 'CVE-2009-1864', 'CVE-2009-1865', 'CVE-2009-1866',
                'CVE-2009-1867', 'CVE-2009-1868', 'CVE-2009-1869', 'CVE-2009-1870');
  script_bugtraq_id(35759, 35900, 35901, 35902, 35903, 35904, 35905, 35906, 35907, 35908
    # 35890                             it's been retired.
  );
  script_osvdb_id(
    56282,
    56771,
    56772,
    56773,
    56774,
    56775,
    56776,
    56777,
    56778
  );

  script_name(english:"Adobe AIR < 1.5.2 Multiple Vulnerabilities (APSB09-10)");
  script_summary(english:"Checks version of Adobe AIR");

   script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a version of Adobe AIR that is affected by 
multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe AIR Player that 
is earlier than 1.5.2. Such versions are reportedly affected by
multiple vulnerabilities : 

  - A memory corruption vulnerability that could potentially
    lead to code execution. (CVE-2009-1862) 

  - A privilege escalation vulnerability that could
    potentially lead to code execution. (CVE-2009-1863) 

  - A heap overflow vulnerability that could potentially
    lead to code execution. (CVE-2009-1864) 

  - A NULL pointer vulnerability that could potentially
    lead to code execution. (CVE-2009-1865) 

  - A stack overflow vulnerability that could potentially
    lead to code execution. (CVE-2009-1866) 

  - A clickjacking vulnerability that could allow an
    attacker to lure a web browser user into unknowingly
    clicking on a link or dialog. (CVE-2009-1867

  - A URL parsing heap overflow vulnerability that could
    potentially lead to code execution. (CVE-2009-1868)

  - An integer overflow vulnerability that could potentially
    lead to code execution. (CVE-2009-1869) 

  - A local sandbox vulnerability that could potentially
    lead to information disclosure when SWFs are saved to
    the hard drive. CVE-2009-1870)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-10.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR version 1.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(59, 94, 119, 189, 200, 264);

  script_set_attribute(attribute:'vuln_publication_date', value:'2009/07/28');
  script_set_attribute(attribute:'patch_publication_date', value:'2009/07/30');
  script_set_attribute(attribute:'plugin_publication_date', value:'2009/07/31');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
version = get_kb_item("SMB/Adobe_AIR/Version");
if (isnull(version)) exit(1, "SMB/Adobe_AIR/Version KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] <= 1)
    )
  )
)
{
  if (report_verbosity > 0 && version_ui)
  {
    report = string(
      "\n",
      "Adobe AIR ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected.");
