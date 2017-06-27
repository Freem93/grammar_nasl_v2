
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59191);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 15:13:58 $");

  script_cve_id("CVE-2012-1149", "CVE-2012-2149", "CVE-2012-2334");
  script_bugtraq_id(53570);
  script_osvdb_id(81988, 81989, 82517);

  script_name(english:"Apache OpenOffice < 3.4.0 Multiple Memory Corruption Vulnerabilities");
  script_summary(english:"Checks the version of Apache OpenOffice.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a program affected by multiple 
memory corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apache OpenOffice installed on the remote host is prior
to 3.4.0. It is, therefore, affected by several memory corruption 
issues :

  - An integer overflow error exists in 'vclmi.dll' that
    could allow heap-based buffer overflows when handling
    embedded image objects. (CVE-2012-1149)

  - A memory overwrite error exists in 'libwpd' that could 
    be triggered when processing WordPerfect documents. This
    memory overwrite may lead to arbitrary code execution.
    (CVE-2012-2149)

  - Memory checking errors exist in
    'filter/source/msfilter msdffimp.cxx' that could be
    triggered when processing PowerPoint graphics records.
    These errors could allow denial of service attacks.
    (CVE-2012-2334)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522780/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2012-1149.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2012-2149.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2012-2334.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/news/aoo34.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache OpenOffice version 3.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("SMB/OpenOffice/Build");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

build = get_kb_item_or_exit("SMB/OpenOffice/Build");
path  = get_kb_item("SMB/OpenOffice/Path");
version_ui = get_kb_item("SMB/OpenOffice/Version_UI");

matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
if (isnull(matches)) audit(AUDIT_VER_FAIL, "OpenOffice");

buildid = int(matches[2]);
if (buildid < 9590) 
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 3.4.0 (340m1 / build 9590)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "OpenOffice", version_ui, path);
