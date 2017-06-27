#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73764);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/30 01:31:24 $");

  script_name(english:"Opera < 12.17 opera_autoupdate.exe MITM Vulnerability");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser component that is affected by a
man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is prior to version
12.17, and thus includes an automatic update-checking component,
'opera_autoupdate.exe', that is vulnerable to man-in-the- middle
attacks because it does not properly verify server certificates.");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1217/");
  script_set_attribute(attribute:"see_also", value:"http://blogs.opera.com/security/2014/04/heartbleed-heartaches/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 12.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");
path = get_kb_item_or_exit("SMB/Opera/Path");

version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

fixed_version = "12.17.1863.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "12.17")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "12.17";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);
