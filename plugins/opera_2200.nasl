#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74362);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id(
    "CVE-2014-1743",
    "CVE-2014-1744",
    "CVE-2014-1745",
    "CVE-2014-1746",
    "CVE-2014-1747",
    "CVE-2014-1748",
    "CVE-2014-1749",
    "CVE-2014-3152",
    "CVE-2014-3803"
  );
  script_bugtraq_id(67237, 67517, 67582);
  script_osvdb_id(
    107139,
    107140,
    107141,
    107142,
    107143,
    107144,
    107145,
    107165,
    107253
  );

  script_name(english:"Opera < 22 Multiple Chromium Vulnerabilities");
  script_summary(english:"Checks version number of Opera.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is prior to version
22. It is, therefore, reportedly affected by multiple vulnerabilities
in the bundled version of Chromium :

  - Use-after-free errors exist related to 'styles' and
    'SVG' handling. (CVE-2014-1743, CVE-2014-1745)

  - An integer overflow error exists related to audio
    handling. (CVE-2014-1744)

  - An out-of-bounds read error exists related to media
    filters. (CVE-2014-1746)

  - A user-input validation error exists related to
    handling local MHTML files that could allow
    for universal cross-site scripting (UXSS) attacks.
    (CVE-2014-1747)

  - An unspecified error exists related to the scrollbar
    that could allow UI spoofing. (CVE-2014-1748)

  - Various unspecified errors. (CVE-2014-1749)

  - An integer underflow error exists related to the V8
    JavaScript engine that could allow a denial of service
    condition. (CVE-2014-3152)

  - An error exists related to the 'Blick' 'SpeechInput'
    feature that could allow click-jacking and information
    disclosure. (CVE-2014-3803)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://blogs.opera.com/desktop/changelog22/");
  # http://googlechromereleases.blogspot.com/2014/05/stable-channel-update_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2da726ba");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/unified/2200/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version", "SMB/Opera/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");
path    = get_kb_item_or_exit("SMB/Opera/Path");

version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

if (get_kb_item("SMB/Opera/supported_classic_branch")) audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);

fixed_version = "22.0.1471.50";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "22.0")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "22.0";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

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
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);
