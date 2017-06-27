#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(80174);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2010-2581",
    "CVE-2010-2582",
    "CVE-2010-3653",
    "CVE-2010-3655",
    "CVE-2010-4084",
    "CVE-2010-4085",
    "CVE-2010-4086",
    "CVE-2010-4087",
    "CVE-2010-4088",
    "CVE-2010-4089",
    "CVE-2010-4090"
  );
  script_bugtraq_id(
    44291,
    44512,
    44513,
    44514,
    44515,
    44516,
    44517,
    44518,
    44510,
    44520,
    44521
  );
  script_osvdb_id(
    68803,
    69189,
    69191,
    69192,
    69193,
    69194,
    69195,
    69196,
    69197,
    69198,
    69208
  );
  script_xref(name:"CERT", value:"402231");

  script_name(english:"Adobe Shockwave Player <= 11.5.8.612 (APSB10-25) (Mac OS X)");
  script_summary(english:"Checks the version of Shockwave Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser plugin that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host contains a version of Adobe Shockwave Player
that is 11.5.8.612 or earlier. It is, therefore, affected by multiple
vulnerabilities :

  - A memory corruption issue exists that allows code
    execution. Note that there are reports that this issue
    is being exploited in the wild. (CVE-2010-3653)

  - A heap-based buffer overflow vulnerability allows code
    execution. (CVE-2010-2582)

  - Multiple memory corruption issues in the 'dirapi.dll'
    module allow code execution. (CVE-2010-2581,
    CVE-2010-3655, CVE-2010-4084, CVE-2010-4085,
    CVE-2010-4086, CVE-2010-4088)

  - Multiple memory corruption issues in the 'IML32.dll'
    module allow code execution. (CVE-2010-4087,
    CVE-2010-4089)

  - A memory corruption issue allows code execution.
    (CVE-2010-4090)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-25.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.5.9.615 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Shockwave rcsL Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("shockwave_player_detect_macosx.nbin");
  script_require_keys("installed_sw/Shockwave Player", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app = 'Shockwave Player';

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver = install['version'];
path = install['path'];

if (ver_compare(ver:ver, fix:'11.5.8.612', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed versions    : 11.5.9.615' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
