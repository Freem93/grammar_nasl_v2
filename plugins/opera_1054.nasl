#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47113);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id(
    "CVE-2010-2421",
    "CVE-2010-2660",
    "CVE-2010-2661",
    "CVE-2010-2665",
    "CVE-2010-2666"
  );
  script_bugtraq_id(40973);
  script_osvdb_id(65717, 66283, 66284, 66288, 66289);
  script_xref(name:"Secunia", value:"40250");

  script_name(english:"Opera < 10.54 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
10.54.  Such versions are potentially affected by the following 
issues :

  - Web fonts may be used to trigger a privilege elevation
    vulnerability in the Windows operating system (MS10-032)
    (954)

  - It may be possible to use data URIs in a cross-site 
    scripting attack. (955)

  - File inputs may disclose the path to selected files. 
    (960)

  - It may be possible to use certain characters for domain 
    name spoofing. (961)

  - It may be possible for a widget to use unrestricted file
    I/O to execute arbitrary code. (962)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1054/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/954/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/955/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/960/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/961/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/962/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 10.54 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/22");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(1, "The 'SMB/Opera/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 10 ||
  (ver[0] == 10 && ver[1] < 54)
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item('SMB/Opera/Path');
    if (isnull(path)) path = 'n/a';

    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : 10.54\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
