#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88984);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2016-0794", "CVE-2016-0795");
  script_bugtraq_id(74334);
  script_osvdb_id(134627, 134628);

  script_name(english:"LibreOffice < 5.0.5 Multiple RCE (Mac OS X)");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote Mac OS X host is
prior to 5.0.5. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists due to
    improper validation of user-supplied input when handling
    LotusWordPro (LWP) documents. A remote attacker can
    exploit this, via a crafted LWP document, to corrupt
    memory, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2016-0794)

  - A remote code execution vulnerability exists due to
    improper validation of user-supplied input when handling
    LwpTocSuperLayout records. A remote attacker can exploit
    this, via a crafted LwpTocSuperLayout record in a
    LotusWordPro (LWP) document, to corrupt memory,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-0795)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 5.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/about-us/security/advisories/cve-2016-0794/");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/about-us/security/advisories/cve-2016-0795/");
  script_set_attribute(attribute:"see_also", value:"http://listarchives.documentfoundation.org/www/announce/msg00258.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "LibreOffice";

get_kb_item_or_exit("Host/MacOSX/Version");

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version    = install['version'];
path       = install['path'];

if (
  # < 5.x
  version =~ "^[0-4]($|[^0-9])" ||
  # 5.0 < 5.0.5
  version =~ "^5\.0\.[0-4]($|[^0-9])"
)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version_ui +
    '\n  Fixed version     : 5.1.0 / 5.0.5 (5.0.5.2)' +
    '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
