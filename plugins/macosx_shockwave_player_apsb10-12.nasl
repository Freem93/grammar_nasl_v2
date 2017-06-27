#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80172);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/03 20:33:39 $");

  script_cve_id(
    "CVE-2010-0127",
    "CVE-2010-0128",
    "CVE-2010-0129",
    "CVE-2010-0130",
    "CVE-2010-0986",
    "CVE-2010-0987",
    "CVE-2010-1280",
    "CVE-2010-1281",
    "CVE-2010-1282",
    "CVE-2010-1283",
    "CVE-2010-1284",
    "CVE-2010-1286",
    "CVE-2010-1287",
    "CVE-2010-1288",
    "CVE-2010-1289",
    "CVE-2010-1290",
    "CVE-2010-1291",
    "CVE-2010-1292"
  );
  script_bugtraq_id(
    40076,
    40077,
    40078,
    40079,
    40081,
    40082,
    40083,
    40084,
    40085,
    40086,
    40087,
    40088,
    40089,
    40090,
    40091,
    40093,
    40094,
    40096
  );
  script_osvdb_id(
    64640,
    64641,
    64642,
    64643,
    64644,
    64645,
    64646,
    64647,
    64648,
    64649,
    64650,
    64651,
    64652,
    64653,
    64654,
    64655,
    64656,
    64657
  );

  script_name(english:"Adobe Shockwave Player <= 11.5.6.606 Multiple Vulnerabilities (APSB10-12) (Mac OS X)");
  script_summary(english:"Checks the version of Shockwave Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser plugin that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host contains a version of Adobe Shockwave Player
that is 11.5.6.606 or earlier. It is, therefore, affected by multiple
vulnerabilities :

  - Processing specially crafted FFFFFF45h Shockwave
    3D blocks results in memory corruption. (CVE-2010-0127,
    CVE-2010-1283)

  - A signedness error leads to memory corruption when
    processing specially crafted Director files.
    (CVE-2010-0128)

  - An array indexing error leads to memory corruption when
    processing specially crafted Director files.
    (CVE-2010-0129)

  - An integer overflow vulnerability leads to memory
    corruption when processing specially crafted Director
    files. (CVE-2010-0130)

  - An unspecified error when processing asset entries
    in Director files leads to memory corruption.
    (CVE-2010-0986)

  - A boundary error when processing embedded fonts from a
    Directory file leads to memory corruption.
    (CVE-2010-0987)

  - An unspecified error when processing Director files
    results in memory corruption. (CVE-2010-1280)

  - Several unspecified memory corruption vulnerabilities.
    (CVE-2010-1281, CVE-2010-1282, CVE-2010-1284,
    CVE-2010-1286, CVE-2010-1287, CVE-2010-1288,
    CVE-2010-1289, CVE-2010-1290, CVE-2010-1291,
    CVE-2010-1292)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-087/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-088/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-089/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19865c37");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/May/130");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/May/131");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/May/132");
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4937.php");
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/adobe-director-invalid-read");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-12.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.5.7.609 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/11");
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

if (ver_compare(ver:ver, fix:'11.5.6.606', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed versions    : 11.5.7.609' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
