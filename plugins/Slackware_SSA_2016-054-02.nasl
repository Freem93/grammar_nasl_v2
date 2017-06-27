#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2016-054-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88910);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2015-7547");
  script_xref(name:"SSA", value:"2016-054-02");
  script_xref(name:"IAVA", value:"2016-A-0053");
  script_xref(name:"TRA", value:"TRA-2017-08");

  script_name(english:"Slackware 14.1 / current : glibc (SSA:2016-054-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New glibc packages are available for Slackware 14.1 and -current to
fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2016&m=slackware-security.569827
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b214cba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-solibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"14.1", pkgname:"glibc", pkgver:"2.17", pkgarch:"i486", pkgnum:"11_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"glibc-i18n", pkgver:"2.17", pkgarch:"i486", pkgnum:"11_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"glibc-profile", pkgver:"2.17", pkgarch:"i486", pkgnum:"11_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"glibc-solibs", pkgver:"2.17", pkgarch:"i486", pkgnum:"11_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"glibc", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"11_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"11_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"11_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"11_slack14.1")) flag++;

if (slackware_check(osver:"current", pkgname:"glibc", pkgver:"2.23", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-i18n", pkgver:"2.23", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-profile", pkgver:"2.23", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-solibs", pkgver:"2.23", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc", pkgver:"2.23", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.23", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.23", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.23", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
