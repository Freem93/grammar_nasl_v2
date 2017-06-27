#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72884);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/04/30 01:31:24 $");

  script_cve_id(
    "CVE-2013-6663",
    "CVE-2013-6664",
    "CVE-2013-6665",
    "CVE-2013-6666",
    "CVE-2013-6667",
    "CVE-2013-6668"
  );
  script_bugtraq_id(65966);
  script_osvdb_id(
    103938,
    103939,
    103940,
    103941,
    103942,
    103943,
    103944,
    103945,
    103946,
    103947,
    103948,
    103949,
    103950,
    103951,
    103952,
    103953,
    103984,
    104059,
    104068
  );

  script_name(english:"Opera < 20 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is a version prior
to version 20. It is, therefore, reportedly affected by multiple
unspecified vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/unified/2000/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/07");

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

if (get_kb_item("SMB/Opera/supported_classic_branch"))
  audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);

fixed_version = "20.0.1387.64";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "20.0")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "20.0";

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
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);
