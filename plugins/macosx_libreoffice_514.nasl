#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91975);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2016-4324");
  script_bugtraq_id(91499);
  script_osvdb_id(140635);

  script_name(english:"LibreOffice < 5.1.4 RTF Character Style Index RCE (macOS)");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote macOS or Mac OS X
host is prior to 5.1.4. It is, therefore, affected by a use-after-free
error due to improper handling of the character style index when
parsing RTF files. An unauthenticated, remote attacker can exploit
this, by convincing a user to open a specially crafted RTF file, to
execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 5.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2016-4324/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13884491");
  # http://blog.talosintel.com/2016/06/vulnerability-spotlight-libreoffice-rtf.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9f01c39");
  # http://www.talosintelligence.com/reports/TALOS-2016-0126/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc117572");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
  # 5.0 < 5.1
  version =~ "^5\.0($|[^0-9])" ||
  # 5.1 < 5.1.4
  version =~ "^5\.1($|\.[0-3])($|[^0-9])"
)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.1.4' +
    '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
