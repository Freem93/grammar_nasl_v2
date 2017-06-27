#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80173);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/23 13:47:46 $");

  script_cve_id(
    "CVE-2010-2863",
    "CVE-2010-2864",
    "CVE-2010-2865",
    "CVE-2010-2866",
    "CVE-2010-2867",
    "CVE-2010-2868",
    "CVE-2010-2869",
    "CVE-2010-2870",
    "CVE-2010-2871",
    "CVE-2010-2872",
    "CVE-2010-2873",
    "CVE-2010-2874",
    "CVE-2010-2875",
    "CVE-2010-2876",
    "CVE-2010-2877",
    "CVE-2010-2878",
    "CVE-2010-2879",
    "CVE-2010-2880",
    "CVE-2010-2881",
    "CVE-2010-2882"
  );
  script_bugtraq_id(
    42664,
    42665,
    42666,
    42667,
    42668,
    42669,
    42670,
    42671,
    42672,
    42673,
    42674,
    42675,
    42676,
    42677,
    42678,
    42679,
    42680,
    42682,
    42683,
    42684
  );
  script_osvdb_id(
    67422,
    67423,
    67424,
    67425,
    67426,
    67427,
    67428,
    67429,
    67430,
    67431,
    67432,
    67433,
    67434,
    67435,
    67436,
    67437,
    67438,
    67439,
    67440,
    67441
  );

  script_name(english:"Adobe Shockwave Player <= 11.5.7.609 (APSB10-20) (Mac OS X)");
  script_summary(english:"Checks the version of Shockwave Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser plugin that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host contains a version of Adobe Shockwave Player
that is 11.5.7.609 or earlier. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist that allow
    arbitrary code execution. (CVE-2010-2863,
    CVE-2010-2864, CVE-2010-2866, CVE-2010-2869,
    CVE-2010-2870, CVE-2010-2871, CVE-2010-2872,
    CVE-2010-2873, CVE-2010-2873, CVE-2010-2874,
    CVE-2010-2875, CVE-2010-2876, CVE-2010-2877,
    CVE-2010-2878, CVE-2010-2880, CVE-2010-2881,
    CVE-2010-2882)

  - A pointer offset vulnerability exists that allows code
    execution. (CVE-2010-2867)

  - Multiple unspecified denial of service issues exist.
    (CVE-2010-2865, CVE-2010-2868)

  - An integer overflow vulnerability exists that allows
    to code execution. (CVE-2010-2879)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-20.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.5.8.612 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

if (ver_compare(ver:ver, fix:'11.5.7.609', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed versions    : 11.5.8.612' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
