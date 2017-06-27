#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2007-316-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(28149);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2007-3387", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);
  script_osvdb_id(38120, 39541, 39542, 39543);
  script_xref(name:"SSA", value:"2007-316-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 / 12.0 / 9.1 / current : xpdf/poppler/koffice/kdegraphics (SSA:2007-316-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New xpdf packages are available for Slackware 9.1, 10.0, 10.1, 10.2,
11.0, 12.0, and -current. New poppler packages are available for
Slackware 12.0 and -current. New koffice packages are available for
Slackware 11.0, 12.0, and -current. New kdegraphics packages are
available for Slackware 10.2, 11.0, 12.0, and -current. These updated
packages address similar bugs which could be used to crash
applications linked with poppler or that use code from xpdf through
the use of a malformed PDF document. It is possible that a maliciously
crafted document could cause code to be executed in the context of the
user running the application processing the PDF. These advisories and
CVE entries cover the bugs:
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3387
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4352
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5392
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5393
http://www.kde.org/info/security/advisory-20071107-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20071107-1.txt"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.761882
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17a94089"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"Slackware Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);


flag = 0;
if (slackware_check(osver:"9.1", pkgname:"xpdf", pkgver:"3.02pl2", pkgarch:"i486", pkgnum:"1_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"xpdf", pkgver:"3.02pl2", pkgarch:"i486", pkgnum:"1_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"xpdf", pkgver:"3.02pl2", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"kdegraphics", pkgver:"3.4.2", pkgarch:"i486", pkgnum:"3_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"xpdf", pkgver:"3.02pl2", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"kdegraphics", pkgver:"3.5.4", pkgarch:"i486", pkgnum:"2_slack11.0")) flag++;
if (slackware_check(osver:"11.0", pkgname:"koffice", pkgver:"1.5.2", pkgarch:"i486", pkgnum:"5_slack11.0")) flag++;
if (slackware_check(osver:"11.0", pkgname:"xpdf", pkgver:"3.02pl2", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"kdegraphics", pkgver:"3.5.7", pkgarch:"i486", pkgnum:"2_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"koffice", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"2_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"poppler", pkgver:"0.6.2", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"xpdf", pkgver:"3.02pl2", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;

if (slackware_check(osver:"current", pkgname:"kdegraphics", pkgver:"3.5.8", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"koffice", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"poppler", pkgver:"0.6.2", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"xpdf", pkgver:"3.02pl2", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
