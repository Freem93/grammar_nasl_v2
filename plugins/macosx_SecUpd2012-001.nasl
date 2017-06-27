#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57798);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2010-1637",
    "CVE-2010-2813",
    "CVE-2010-4554",
    "CVE-2010-4555",
    "CVE-2011-0200",
    "CVE-2011-1148",
    "CVE-2011-1657",
    "CVE-2011-1752",
    "CVE-2011-1783",
    "CVE-2011-1921",
    "CVE-2011-1938",
    "CVE-2011-2023",
    "CVE-2011-2192",
    "CVE-2011-2202",
    "CVE-2011-2204",
    "CVE-2011-2483",
    "CVE-2011-2895",
    "CVE-2011-3182",
    "CVE-2011-3189",
    "CVE-2011-3248",
    "CVE-2011-3249",
    "CVE-2011-3250",
    "CVE-2011-3252",
    "CVE-2011-3267",
    "CVE-2011-3268",
    "CVE-2011-3348",
    "CVE-2011-3389",
    "CVE-2011-3422",
    "CVE-2011-3446",
    "CVE-2011-3448",
    "CVE-2011-3449",
    "CVE-2011-3453",
    "CVE-2011-3457",
    "CVE-2011-3458",
    "CVE-2011-3459",
    "CVE-2011-3460"
  );
  script_bugtraq_id(
    40291,
    42399,
    46843,
    47950,
    48091,
    48259,
    48416,
    48434,
    48456,
    48648,
    49124,
    49241,
    49249,
    49252,
    49376,
    49429,
    49616,
    49778,
    50065,
    50400,
    50401,
    50404,
    51807,
    51808,
    51809,
    51811,
    51812,
    51814,
    51817,
    51832
  );
  script_osvdb_id(
    65696,
    67245,
    72644,
    73113,
    73218,
    73245,
    73246,
    73247,
    73328,
    73364,
    73429,
    73686,
    74083,
    74084,
    74085,
    74088,
    74089,
    74726,
    74738,
    74739,
    74742,
    74743,
    74829,
    74927,
    75200,
    75446,
    75647,
    76381,
    76541,
    76542,
    76543,
    78313,
    78803,
    78805,
    78806,
    78809,
    78810,
    78811,
    78812,
    78813
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-02-03-1");
  script_xref(name:"CERT", value:"403593");
  script_xref(name:"CERT", value:"410281");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2012-001) (BEAST)");
  script_summary(english:"Check for the presence of Security Update 2012-001.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.6 that does not
have Security Update 2012-001 applied. This update contains multiple
security-related fixes for the following components :

  - Apache
  - ATS
  - ColorSync
  - CoreAudio
  - CoreMedia
  - CoreText
  - curl
  - Data Security
  - dovecot
  - filecmds
  - libresolv
  - libsecurity
  - OpenGL
  - PHP
  - QuickTime
  - SquirrelMail
  - Subversion
  - Tomcat
  - X11"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-058/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-103/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-130/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/59");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5130");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Feb/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Feb/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2012-001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.6");

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
if (
  egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2012\.00[1-9]|201[3-9]\.[0-9]+)(\.snowleopard[0-9.]*)?\.bom", string:packages) ||
  egrep(pattern:"^com\.apple\.pkg\.update\.security\.2012\.001(\.snowleopard)?\.1\.1\.bom", string:packages)
) exit(0, "The host has Security Update 2012-001 or later installed and therefore is not affected.");
else
{
  if (report_verbosity > 0)
  {
    security_boms = egrep(pattern:"^com\.apple\.pkg\.update\.security", string:packages);

    report = '\n  Installed security updates : ';
    if (security_boms) report += str_replace(find:'\n', replace:'\n                               ', string:security_boms);
    else report += 'n/a';
    report += '\n';

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
