#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47583);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2012/02/09 20:40:56 $");

  script_cve_id(
    "CVE-2010-2657",
    "CVE-2010-2658",
    # "CVE-2010-2659",  # nb: the 10.60 fix is in the Unix variant.
    "CVE-2010-2662",
    "CVE-2010-2663",
    "CVE-2010-2664"
  );
  script_bugtraq_id(41284, 41669);
  script_osvdb_id(66224, 66225, 66285, 66286, 66287);
  script_xref(name:"Secunia", value:"40375");

  script_name(english:"Opera < 10.60 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
10.60.  Such versions are potentially affected by the following 
issues :

  - A delay, inserted after a user clicks on a link, is not
    functioning correctly and allows a user's double-click
    to interact with the download dialog immediately.  This
    can allow unexpected execution of programs from the 
    website if the download dialog appears under the pointer
    location. (957)

  - Files, whose filename and path have been pulled from
    the clipboard, may be unintentionally uploaded to a 
    server without user authorization. This does require
    the user to have focused a file input and pasted the
    clipboard contents. (958)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1060/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/957/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/958/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 10.60 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
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

version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(1, "The 'SMB/Opera/Version' KB item is missing.");
version_ui = get_kb_item("SMB/Opera/Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

install_path = get_kb_item('SMB/Opera/Path');

if (ver_compare(ver:version, fix:'10.60.3445.0') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : 10.60' + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
