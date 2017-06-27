#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51774);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id(
    "CVE-2011-0450",
    "CVE-2011-0681",
    "CVE-2011-0682",
    "CVE-2011-0683",
    "CVE-2011-0684",
    "CVE-2011-0685",
    "CVE-2011-0686",
    "CVE-2011-0687"
  );
  script_bugtraq_id(45951, 46003, 46036);
  script_osvdb_id(
    70726,
    70727,
    70728,
    70729,
    70730,
    70731,
    70732,
    70733
  );
  script_xref(name:"EDB-ID", value:"16042");
  script_xref(name:"Secunia", value:"43023");

  script_name(english:"Opera < 11.01 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote Windows host is earlier
than 11.01.  Such versions are potentially affected by the following
issues :

  - The Cascading Style Sheets (CSS) Extensions for XML 
    implementation recognizes links to javascript: URLs in 
    the -o-link property, which could be abused to bypass
    CSS filtering. (CVE-2011-0681)

  - An integer truncation error exists such that the 
    application may crash when accessing web pages that
    contain forms having large numbers of items in an  
    'option' element. Such crashes may lead to memory 
    corruption and allow code execution. (982)

  - An error exists in the handling of internal 'opera:' 
    URLS that can allow anti-clickjacking configuration
    options to be modified. (983)

  - An error exists in the processing of certain HTTP
    requests and responses that can allow limited,
    unauthorized access to local files. (984)

  - An error exists in the downloads manager that allows
    unintended executables to be used when attempting to 
    open the folder containing a downloaded file. (985)

  - An error exists in the private data deletion process
    that causes the removal of email passwords to be
    delayed. (986)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/982/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/983/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/984/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/985/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/986/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1101/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 11.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

if (ver_compare(ver:version, fix:'11.1.1190.0') == -1)
{
  if (report_verbosity > 0)
  {
    install_path = get_kb_item("SMB/Opera/Path");

    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : 11.01\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
