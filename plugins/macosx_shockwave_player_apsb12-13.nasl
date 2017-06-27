#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80180);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/03 20:33:39 $");

  script_cve_id(
    "CVE-2012-2029",
    "CVE-2012-2030",
    "CVE-2012-2031",
    "CVE-2012-2032",
    "CVE-2012-2033"
  );
  script_bugtraq_id(53420);
  script_osvdb_id(81748, 81749, 81750, 81751, 81752);

  script_name(english:"Adobe Shockwave Player <= 11.6.4.634 Multiple Memory Corruption Vulnerabilities (APSB12-13) (Mac OS X)");
  script_summary(english:"Checks the version of Shockwave Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser plugin that is
affected by multiple memory corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host contains a version of Adobe Shockwave Player
that is 11.6.4.634 or earlier. It is, therefore, affected by multiple
unspecified memory corruption vulnerabilities.

A remote attacker can exploit these issues by tricking a user into
viewing a malicious Shockwave file, resulting in arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-13.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/May/71");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/May/72");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/May/73");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Shockwave Player 11.6.5.635 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
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

if (ver_compare(ver:ver, fix:'11.6.4.634', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed versions    : 11.6.5.635' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
