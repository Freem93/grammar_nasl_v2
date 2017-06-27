#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99310);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2013-6629");
  script_bugtraq_id(63676);
  script_osvdb_id(99711);
  script_xref(name:"MSKB", value:"4019460");

  script_name(english:"KB4019460: Security Update for the libjpeg Information Disclosure Vulnerability for Mono Framework (macOS)");
  script_summary(english:"Checks the version of Mono.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Mono Framework application installed on the remote macOS or Mac
OS X host is missing security update KB4019460. It is, therefore,
affected by an information disclosure vulnerability in the libjpeg and
libjpeg-turbo libraries of Mono Framework. An unauthenticated, remote
attacker can exploit this, via a specially crafted JPEG image, to 
disclose potentially sensitive information from uninitialized memory.");
  script_set_attribute(attribute:"see_also",value:"https://support.microsoft.com/en-us/help/4019460/title");
  script_set_attribute(attribute:"solution", value:
"Install security update KB4019460.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mono:mono");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_mono_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "installed_sw/Mono");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

matches = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

mac_version = matches[1];
if (mac_version !~ "^10\.([789]|1[012])($|[^0-9])")
audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", mac_version);

app = "Mono";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path    = install['path'];

fix = NULL;
if (version =~ "^5\.")
{
  if (version !~ "^\d+\.\d+\.\d+\.\d+")
    audit(AUDIT_VER_NOT_GRANULAR, app, version);
  fix = "5.0.0.48";
}
else if (version =~ "^[0-4]\.")
  fix = "4.8.1";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
