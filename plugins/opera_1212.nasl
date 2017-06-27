#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63301);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/01/02 12:11:04 $");

  script_cve_id("CVE-2012-6470", "CVE-2012-6471");
  script_bugtraq_id(56788, 56984);
  script_osvdb_id(88101, 88657);
  script_xref(name:"EDB-ID", value:"23107");

  script_name(english:"Opera < 12.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than 12.12
and is, therefore, reportedly affected by the following 
vulnerabilities :

  - An error exists related to GIF image file handling that
    can allow heap memory corruption and can lead to
    application crashes or arbitrary code execution. (1038)

  - An error exists related to URL handling and the address
    bar that can allow rapid, repeated web requests to
    cause the incorrect URL to be displayed. (1040)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/54");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1038/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1040/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/unified/1212/");
  script_set_attribute(attribute:"solution", value: "Upgrade to Opera 12.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

fixed_version = "12.12.1707.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "12.12")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "12.12";

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
