#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59089);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/08/06 10:44:51 $");

  script_cve_id("CVE-2012-3561");
  script_bugtraq_id(53474);
  script_osvdb_id(81809);

  script_name(english:"Opera < 11.64 URL Parsing Memory Corruption");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is potentially affected
by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote Windows host is earlier
than 11.64 and is, therefore, potentially affected by a memory
corruption vulnerability. 

Certain crafted URLs can cause the application to allocate incorrect
amounts of memory and overwrite unrelated memory. This corruption can
then lead to application crashes or even arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1016/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1164/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 11.64 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Opera/Path");
version = get_kb_item_or_exit("SMB/Opera/Version");
version_ui = get_kb_item("SMB/Opera/Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui; 

fixed_version = "11.64.1403.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "11.64")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else
  fixed_version_report = "11.64";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);
