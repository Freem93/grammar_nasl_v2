#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(80179);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/23 13:47:46 $");

  script_cve_id(
    "CVE-2012-0757",
    "CVE-2012-0758",
    "CVE-2012-0759",
    "CVE-2012-0760",
    "CVE-2012-0761",
    "CVE-2012-0762",
    "CVE-2012-0763",
    "CVE-2012-0764",
    "CVE-2012-0766"
  );
  script_bugtraq_id(
    51999,
    52000,
    52001,
    52002,
    52003,
    52004,
    52005,
    52006,
    52007
  );
  script_osvdb_id(
    79237,
    79238,
    79239,
    79240,
    79241,
    79242,
    79243,
    79244,
    79245
  );

  script_name(english:"Adobe Shockwave Player <= 11.6.3.633 Multiple Code Execution Vulnerabilities (APSB12-02) (Mac OS X)");
  script_summary(english:"Checks the version of Shockwave Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser plugin that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host contains a version of Adobe Shockwave Player
that is 11.6.3.633 or earlier. It is, therefore, affected by multiple
code execution vulnerabilities.

  - Multiple memory corruption issues exist related to the
    Shockwave 3D Asset that allow code execution.
    (CVE-2012-0757, CVE-2012-0760, CVE-2012-0761,
    CVE-2012-0762, CVE-2012-0763, CVE-2012-0764,
    CVE-2012-0766)

  - An unspecified heap-based buffer overflow exists that
    allows code execution. (CVE-2012-0758)

  - An unspecified memory corruption vulnerability exists
    that allows to code execution. (CVE-2012-0759)

A remote attacker can exploit these issues by tricking a user into
viewing a malicious Shockwave file, resulting in arbitrary code
execution.");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-02.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave 11.6.4.634 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
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

if (ver_compare(ver:ver, fix:'11.6.3.633', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed versions    : 11.6.4.634' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
