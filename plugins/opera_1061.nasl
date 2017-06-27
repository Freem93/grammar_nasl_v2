#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48317);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2012/02/09 20:40:56 $");

  script_cve_id(
    "CVE-2010-2576", 
    "CVE-2010-3019", 
    "CVE-2010-3020",
    "CVE-2010-3021", 
    "CVE-2011-1824"
  );
  script_bugtraq_id(42407, 47764);
  script_osvdb_id(67201, 67202, 67203, 67204, 74176);
  script_xref(name:"Secunia", value:"40120");

  script_name(english:"Opera < 10.61 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
10.61.  Such versions are potentially affected by the following 
issues :

  - A heap overflow when performing painting operations on
    an HTML5 canvas can result in execution of arbitrary
    code. (966)

  - An issue with tab focus is open to an attack
    where it is used to obscure a download dialog that is in
    another tab. The user can be tricked into clicking on
    buttons in the dialog, resulting in the downloaded file 
    being executed. (967)

  - Certain types of content concerning the news feed
    preview do not have their scripts removed properly,
    possibly resulting in subscription of feeds without
    the user's consent. (968)

  - Loading an animated PNG image may cause high CPU usage 
    with no response from the browser. (CVE-2010-3021)

  - An error exists in the handling of 'SELECT' HTML 
    elements having a very large 'size' attribute. This
    error can allow memory corruption and possibly allows
    remote code execution. (CVE-2011-1824)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1061/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/966/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/967/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/968/");
  script_set_attribute(attribute:"see_also", value:"http://www.toucan-system.com/advisories/tssa-2011-02.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 10.61 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/12");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");
version_ui = get_kb_item("SMB/Opera/Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

install_path = get_kb_item_or_exit('SMB/Opera/Path');

if (ver_compare(ver:version, fix:'10.61.3484.0') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : 10.61' + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
