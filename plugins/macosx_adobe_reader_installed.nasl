#TRUSTED 9bcd61734d234f2413b9798efd8a46f1591faa7987723298ec0990a70d00a01838d47407ec7f4d5fe1eb101152fb9797858cb3f3ebf9a84f4e6c596d8060a32373a5cb74a1abd3b69a0a153a41f6dbb2c9fd8a29dd62bcc4aefd28ebd2bad42cbbb4f705238bdac2827960e0314b847f867fb091943cb7fb451787f5ca9e4b5a4e1f16ed50436bddf94f124ea5dc1928910ec5d81ad23d85477f397d1222ab5d1a0c0425b87d20c172b4109afb441a82914f64e65713536b90ee26c11bf31e70fff9af907ef887a2dbc3f8bdc780e9aa4a869a5d091ffcb35de89b3e90cde1f56d9e96c72966df64a622973406c300cf7b6dd8c184b39600cb742bb85f9bc2e14a0a0d9d8d4b6846933e2dd2cb9a7e3fef5c779c2e0f03a49b39d20eea1f5f181b84790862b6452da020d7002605415481ca20e673d535b8e79df1a2629508b7d17565eecc09cb2a5a1026ea4c16b9fdee8958ee80ea6be21e53e40d0711b25acdb6f0f92ac33ac7e0957ed82d76c424da54287f6536c32ec1585332e183759ada75cc85a87e409d37cfcdde05a78df2189ac5c76cc8755688eed9bf2874cfaf727b39f35e2c2a9f07a706c6670331a986f93b79db8c4a82c643d5cf78b027301a9cba98d952c6550fc1159738e9aed489991ec4261ec5a8e4f0bdd671acc4c853c1194073a43a7cde6bd25e11b4b6ce8774eced7fc905840de748baad33ba59
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55420);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/03/17");

  script_name(english:"Adobe Reader Installed (Mac OS X)");
  script_summary(english:"Gets the Reader version from Info.plist.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a PDF file viewer.");
  script_set_attribute(attribute:"description", value:
"Adobe Reader, a PDF file viewer, is installed on the remote Mac OS X
host.");
  script_set_attribute(attribute:"see_also", value:"https://acrobat.adobe.com/us/en/products/pdf-reader.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Adobe_Reader";


cmd = 'find /Applications -name "Adobe Reader*" -o -name "Acrobat Reader*" -o -name "Adobe Acrobat Reader*" -mindepth 1 -maxdepth 1 -type d';
dirs = exec_cmd(cmd:cmd);
if (isnull(dirs)) exit(0, "Adobe Reader does not appear to be installed.");


info = '';
foreach dir (split(dirs, keep:FALSE))
{

  base_dir = dir - "/Applications";

  if ("Acrobat Reader" >< dir &&  "DC" >!< base_dir)
  {
    plist = dir + "/Contents/Info-macos.plist";
  }
  else if (ereg(pattern:"Adobe Reader [67]\.", string:dir))
  {
    plist = dir + base_dir + ".app/Contents/Info-macos.plist";
  }
  else if (ereg(pattern:"Adobe Reader [89]($|[^0-9.])", string:dir))
  {
    plist = dir + "/Adobe Reader.app/Contents/Info.plist";
  }
  else
  {
    plist = dir + "/Contents/Info.plist";
  }

  cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
  if (isnull(version) || version !~ "^[0-9]+\.") version = UNKNOWN_VER;

  info += '\n  Path    : ' + dir +
          '\n  Version : ' + version + '\n';

  set_kb_item(name:kb_base+base_dir+"/Version", value:version);

  register_install(
    app_name:"Adobe Reader",
    path:dir,
    version:version,
    cpe:"cpe:/a:adobe:acrobat_reader");
}


if (info)
{
  set_kb_item(name:kb_base+"/Installed", value:TRUE);

  if (report_verbosity > 0) security_note(port:0, extra:info);
  else security_note(0);
}
else audit(AUDIT_UNKNOWN_APP_VER, "Adobe Reader");
