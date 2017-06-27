#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56568);
  script_version("$Revision: 1.47 $");
  script_cvs_date("$Date: 2013/11/12 02:44:14 $");

  script_name(english:"Mac OS X XProtect Installed");
  script_summary(english:"Checks status of XProtect");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An antivirus program is installed on the remote host, but the program
does not function properly."
  );
  script_set_attribute(
    attribute:"description",
    value:
"There is a problem with the installation of the Apple XProtect
application on the remote Mac OS X host - either updates are not enabled
/ running or its definitions are out of date."
  );
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Xprotect");
  script_set_attribute(attribute:"solution", value:"Make sure updates are working and the associated services are running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("macosx_xprotect_detect.nasl");
  script_require_keys("Antivirus/XProtect/installed", "Host/MacOSX/Version");

  exit(0);
}


include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");


get_kb_item_or_exit("Antivirus/XProtect/installed");


kb_base = 'MacOSX/XProtect/';

info = get_av_info("macosx_xprotect");
if (isnull(info)) exit(1, "Failed to get Mac OS X XProtect info from antivirus.inc.");
latest_defs_ver = make_array();
latest_defs_ver[1] = info["latest_defs_ver[1]"];
latest_defs_ver[2] = info["latest_defs_ver[2]"];
latest_defs_ver[3] = info["latest_defs_ver[3]"];


os = get_kb_item_or_exit("Host/MacOSX/Version");
if (ereg(pattern:"Mac OS X 10\.9([^0-9]|$)", string:os)) exit(0, "The plugin is temporarily disabled on OS X Mavericks.");

last_mod = get_kb_item(kb_base+"LastModification");
defs = get_kb_item(kb_base+"DefinitionsVersion");

problems = 0;
report = '\n' + 'The remote Mac OS X host includes Apple\'s XProtect software.' +
         '\n';

if (last_mod || defs)
{
  report += '\n' + 'Safe Download definitions :';
  if (last_mod) report += '\n  Last updated    : ' + last_mod;
  if (defs)     report += '\n  Current version : ' + defs;
}
if (defs)
{
  if (ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os)) i = 1;
  else if (ereg(pattern:"Mac OS X 10\.7([^0-9]|$)", string:os)) i = 2;
  else if (ereg(pattern:"Mac OS X 10\.8([^0-9]|$)", string:os)) i = 3;
  else if (ereg(pattern:"Mac OS X 10\.9([^0-9]|$)", string:os)) i = 4;
  else exit(0, "The plugin does not support "+os+".");

  # nb: give users a day leeway since XProtect currently updates
  #     only once per day.
  if (ver_compare(ver:defs, fix:int(latest_defs_ver[i])-1, strict:FALSE) == -1)
  {
    problems++;
    report += '\n  Latest version : ' + latest_defs_ver[i] +
              '\n' +
              '\n' + 'Note that the host has an outdated version of the definitions.';
  }
}
else
{
  problems++;
  report += '\n' + 'It was not possible to determine the version of the Safe Download' +
            '\n' + 'definitions.';
}
report += '\n';

if (!get_kb_item(kb_base+"XProtectUpdater/Loaded"))
{
  problems++;
  report += '\n' + 'The XProtectUpdater daemon is not loaded via launchd.' +
            '\n';
}

if (!get_kb_item(kb_base+"XProtectUpdater/Exists"))
{
  problems++;
  report += '\n' + 'The XProtectUpdater daemon does not exist or is an empty file.' +
            '\n';
}

if (!get_kb_item(kb_base+"XProtectUpdater/Configured"))
{
  problems++;
  report += '\n' + 'The XProtectUpdater daemon is not configured for use with launchd.' +
            '\n';
}



if (problems)
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(port:0);
}
else
{
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item (name:"Antivirus/XProtect/description", value:report);
}
