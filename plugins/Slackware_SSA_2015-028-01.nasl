#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2015-028-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81075);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_xref(name:"SSA", value:"2015-028-01");

  script_name(english:"Slackware 13.0 / 13.1 / 13.37 / 14.0 / 14.1 / current : glibc (SSA:2015-028-01) (GHOST)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New glibc packages are available for Slackware 13.0, 13.1, 13.37,
14.0, and 14.1 to fix a security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2015&m=slackware-security.1260924
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccc24009"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-solibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-zoneinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"13.0", pkgname:"glibc", pkgver:"2.9", pkgarch:"i486", pkgnum:"7_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-i18n", pkgver:"2.9", pkgarch:"i486", pkgnum:"7_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-profile", pkgver:"2.9", pkgarch:"i486", pkgnum:"7_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-solibs", pkgver:"2.9", pkgarch:"i486", pkgnum:"7_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"7_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"7_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"7_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.9", pkgarch:"x86_64", pkgnum:"7_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"13.1", pkgname:"glibc", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"9_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-i18n", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"9_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-profile", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"9_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-solibs", pkgver:"2.11.1", pkgarch:"i486", pkgnum:"9_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"9_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"9_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"9_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.11.1", pkgarch:"x86_64", pkgnum:"9_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"glibc", pkgver:"2.13", pkgarch:"i486", pkgnum:"8_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"glibc-i18n", pkgver:"2.13", pkgarch:"i486", pkgnum:"8_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"glibc-profile", pkgver:"2.13", pkgarch:"i486", pkgnum:"8_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"glibc-solibs", pkgver:"2.13", pkgarch:"i486", pkgnum:"8_slack13.37")) flag++;
if (slackware_check(osver:"13.37", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc", pkgver:"2.13", pkgarch:"x86_64", pkgnum:"8_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.13", pkgarch:"x86_64", pkgnum:"8_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.13", pkgarch:"x86_64", pkgnum:"8_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.13", pkgarch:"x86_64", pkgnum:"8_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"14.0", pkgname:"glibc", pkgver:"2.15", pkgarch:"i486", pkgnum:"9_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"glibc-i18n", pkgver:"2.15", pkgarch:"i486", pkgnum:"9_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"glibc-profile", pkgver:"2.15", pkgarch:"i486", pkgnum:"9_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"glibc-solibs", pkgver:"2.15", pkgarch:"i486", pkgnum:"9_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc", pkgver:"2.15", pkgarch:"x86_64", pkgnum:"9_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.15", pkgarch:"x86_64", pkgnum:"9_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.15", pkgarch:"x86_64", pkgnum:"9_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.15", pkgarch:"x86_64", pkgnum:"9_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"14.1", pkgname:"glibc", pkgver:"2.17", pkgarch:"i486", pkgnum:"10_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"glibc-i18n", pkgver:"2.17", pkgarch:"i486", pkgnum:"10_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"glibc-profile", pkgver:"2.17", pkgarch:"i486", pkgnum:"10_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"glibc-solibs", pkgver:"2.17", pkgarch:"i486", pkgnum:"10_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"glibc", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"10_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"10_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"10_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.17", pkgarch:"x86_64", pkgnum:"10_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"glibc", pkgver:"2.20", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-i18n", pkgver:"2.20", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-profile", pkgver:"2.20", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-solibs", pkgver:"2.20", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc", pkgver:"2.20", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.20", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.20", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.20", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-zoneinfo", pkgver:"2014j", pkgarch:"noarch", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
