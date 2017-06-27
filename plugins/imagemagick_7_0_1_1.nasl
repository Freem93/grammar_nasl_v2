#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90892);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/03/22 14:08:09 $");

  script_cve_id(
    "CVE-2016-3714",
    "CVE-2016-3715",
    "CVE-2016-3716",
    "CVE-2016-3717",
    "CVE-2016-3718"
  );
  script_bugtraq_id(
    89848,
    89849,
    89852,
    89861,
    89866
  );
  script_osvdb_id(
    137951,
    137952,
    137953,
    137954,
    137955
  );
  script_xref(name:"CERT", value:"250519");
  script_xref(name:"EDB-ID", value:"39767");
  script_xref(name:"EDB-ID", value:"39791");

  script_name(english:"ImageMagick < 7.0.1-1 / 6.x < 6.9.3-10 Multiple Vulnerabilities (ImageTragick)");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is
prior to 7.0.1-1 or 6.x prior to 6.9.3-10. It is, therefore, affected
by the following vulnerabilities :

  - A remote code execution vulnerability, known as
    ImageTragick, exists due to a failure to properly filter
    shell characters in filenames passed to delegate
    commands. A remote attacker can exploit this, via
    specially crafted images, to inject shell commands and
    execute arbitrary code. (CVE-2016-3714)

  - An unspecified flaw exists in the 'ephemeral' pseudo
    protocol that allows an attacker to delete arbitrary
    files. (CVE-2016-3715)

  - An unspecified flaw exists in the 'ms' pseudo protocol
    that allows an attacker to move arbitrary files to
    arbitrary locations. (CVE-2016-3716)

  - An unspecified flaw exists in the 'label' pseudo
    protocol that allows an attacker, via a specially
    crafted image, to read arbitrary files. (CVE-2016-3717)

  - A server-side request forgery (SSRF) vulnerability
    exists due to an unspecified flaw related to request
    handling between a user and the server. A remote
    attacker can exploit this, via an MVG file with a
    specially crafted fill element, to bypass access
    restrictions and conduct host-based attacks.
    (CVE-2016-3718)");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"see_also", value:"https://www.imagemagick.org/discourse-server/viewtopic.php?f=4&t=29588");
  script_set_attribute(attribute:"see_also", value:"https://imagetragick.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.1-1 / 6.9.3-10 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "ImageMagick";

# Get installs
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
display_version = install['display_version'];
version         = install['version'];
build           = install['build'];
path            = install['path'];

vuln = FALSE;

if (version =~ "^6\.")
{
  fix = "6.9.3";
  fix_build = 10;
}
else if (version =~ "^7\.")
{
  fix = "7.0.1";
  fix_build = 1;
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, display_version, path);

display_fix = fix + "-" + fix_build;

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
  vuln = TRUE;

if ((ver_compare(ver:version, fix:fix, strict:FALSE) == 0)  &&
    build < fix_build
   )
  vuln = TRUE;

if (vuln)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  items = make_array("Installed version", display_version,
                     "Fixed version", display_fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, display_version, path);
