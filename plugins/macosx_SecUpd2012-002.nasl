#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59067);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2011-0241",
    "CVE-2011-1004",
    "CVE-2011-1005",
    "CVE-2011-1167",
    "CVE-2011-1777",
    "CVE-2011-1778",
    "CVE-2011-1944",
    "CVE-2011-2692",
    "CVE-2011-2821",
    "CVE-2011-2834",
    "CVE-2011-3328",
    "CVE-2011-3389",
    "CVE-2011-3919",
    "CVE-2011-4815",
    "CVE-2012-0651",
    "CVE-2012-0654",
    "CVE-2012-0655",
    "CVE-2012-0657",
    "CVE-2012-0658",
    "CVE-2012-0659",
    "CVE-2012-0660",
    "CVE-2012-0662",
    "CVE-2012-0870",
    "CVE-2012-1182"
  );
  script_bugtraq_id(
    46458,
    46460,
    46951,
    47737,
    48056,
    48618,
    48833,
    49279,
    49658,
    49744,
    49778,
    51198,
    51300,
    52103,
    52973,
    53458,
    53462,
    53465,
    53467,
    53468,
    53469,
    53471,
    53473
  );
  script_osvdb_id(
    70957,
    70958,
    71256,
    73248,
    73982,
    73992,
    74695,
    74829,
    75560,
    75676,
    77464,
    77465,
    78118,
    78148,
    79443,
    81303,
    81930,
    81931,
    81932,
    82117,
    82220,
    82222,
    82224,
    82225
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-05-09-1");
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2012-002) (BEAST)");
  script_summary(english:"Check for the presence of Security Update 2012-002");

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
have Security Update 2012-002 applied. This update contains multiple
security-related fixes for the following components :

  - curl
  - Directory Service
  - ImageIO
  - libarchive
  - libsecurity
  - libxml
  - Quartz Composer
  - QuickTime
  - Ruby
  - Samba
  - Security Framework"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-137/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523932/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5281");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/May/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2012-002 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba SetInformationPolicy AuditEventsInfo Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/10");

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
  egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2012\.00[2-9]|201[3-9]\.[0-9]+)(\.snowleopard[0-9.]*)?\.bom", string:packages) ||
  egrep(pattern:"^com\.apple\.pkg\.update\.security\.2012\.002(\.snowleopard)?\.1\.0\.bom", string:packages)
) exit(0, "The host has Security Update 2012-002 or later installed and therefore is not affected.");
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
