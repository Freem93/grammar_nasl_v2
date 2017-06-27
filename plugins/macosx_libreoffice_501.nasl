#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86903);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2015-5214");
  script_osvdb_id(129859);

  script_name(english:"LibreOffice < 4.4.6 / 5.x < 5.0.1 Document Bookmark Arbitrary Code Execution (Mac OS X)");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an
arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote Mac OS X host is
prior to 4.4.6 or 5.x prior to 5.0.1. It is, therefore, affected by a
memory corruption issue in 'filter/ww8/ww8scan.cxx' due to improper
validation of user-supplied input when handling bookmark status
positions. A remote attacker can exploit this, via a specially crafted
document, to cause a denial of service condition or the execution of
arbitrary code.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 4.4.6 (4.4.6.3) / 5.0.1 (5.0.1.2) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2015-5214/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8cc4e31");
  script_set_attribute(attribute:"see_also", value:"http://listarchives.documentfoundation.org/www/announce/msg00243.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
  # < 4.x
  version =~ "^[0-3]($|[^0-9])" ||
  # 4.x < 4.4.6
  version =~ "^(4\.[0-3]|4\.4\.[0-5])($|[^0-9])" ||
  # 5.x < 5.0.1
  version =~ "^5\.0\.0($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.4.6 (4.4.6.3) / 5.0.1 (5.0.1.2)' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
