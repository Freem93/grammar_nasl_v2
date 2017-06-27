#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97496);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/24 19:24:19 $");

  script_cve_id(
    "CVE-2016-10327",
    "CVE-2017-3157",
    "CVE-2017-7870"
  );
  script_bugtraq_id(
    96402,
    97668,
    97671
  );
  script_osvdb_id(
    152405,
    152487,
    152503
  );
  script_xref(name:"IAVB", value:"2017-B-0026");

  script_name(english:"LibreOffice < 5.1.6 / 5.2.5 / 5.3.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote Windows host is
prior to 5.1, 5.1.x prior to 5.1.6, or 5.2.x prior to 5.2.5. It is,
therefore, affected by multiple vulnerabilities :

  - An overflow condition exists when processing EMF files,
    specifically in the EnhWMFReader::ReadEnhWMF() function
    within file vcl/source/filter/wmf/enhwmf.cxx, due to
    improper validation of a certain offset value in the
    header that precedes bitmap data. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted enhanced metafile file (EMF), to cause a denial
    of service condition or the execution of arbitrary code.
    Note that this vulnerability does not affect version
    5.1.x. (CVE-2016-10327)

  - A file disclosure vulnerability exists due to a flaw in
    the content preview feature when handling embedded
    objects. An unauthenticated, remote attacker can exploit
    this, via a specially crafted file, to disclose details
    of a file on the hosting system. (CVE-2017-3157)

  - An overflow condition exists in the Polygon::Insert()
    function within file tools/source/generic/poly.cxx
    when processing polygons in Windows metafiles (WMF) that
    under certain circumstances result in polygons with more
    points than can represented in LibreOffice's internal
    polygon class. An unauthenticated, remote attacker can
    exploit this, via a specially crafted WMF file, to cause
    a denial of service condition or the execution of
    arbitrary code. Note that this vulnerability does not
    affect version 5.1.x. (CVE-2017-7870)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2016-10327/");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2017-3157/");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2017-7870/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 5.1.6 / 5.2.5 / 5.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "LibreOffice";

get_kb_item_or_exit("SMB/Registry/Enumerated");

install    = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version    = install['version'];
version_ui = install['display_version'];
path       = install['path'];

if (
  # < 5.x
  version =~ "^[0-4]($|[^0-9])" ||
  # 5.0 < 5.1
  version =~ "^5\.0($|[^0-9])" ||
  # 5.1 < 5.1.6
  version =~ "^5\.1($|\.[0-5])($|[^0-9])" ||
  # 5.2 < 5.2.5
  version =~ "^5\.2($|\.[0-4])($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version_ui +
    '\n  Fixed version     : 5.1.6 / 5.2.5 / 5.3.0' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui, path);
