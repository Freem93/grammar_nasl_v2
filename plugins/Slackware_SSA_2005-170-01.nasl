#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2005-170-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18802);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/01 00:36:12 $");

  script_osvdb_id(17299, 17340);
  script_xref(name:"SSA", value:"2005-170-01");

  script_name(english:"Slackware 10.0 / 10.1 / 8.1 / 9.0 / 9.1 / current : java (jre, j2sdk) (SSA:2005-170-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun has released a couple of security advisories pertaining to both
the Java Runtime Environment and the Standard Edition Development Kit.
These could allow applets to read or write to local files. For more
details, Sun's advisories may be found here:
http://sunsolve.sun.com/search/document.do?assetkey=1-26-101748-1
http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1
Slackware repackage's Sun's Java(TM) binaries without changing them,
so the packages from Slackware -current should be used for all glibc
based Slackware versions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-101748-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.394829
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0797b66e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected j2sdk and / or jre packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:j2sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"j2sdk", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"8.1", pkgname:"jre", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"j2sdk", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"jre", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.1", pkgname:"j2sdk", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"jre", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"j2sdk", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"jre", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.1", pkgname:"j2sdk", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"jre", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"j2sdk", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"jre", pkgver:"1_5_0_03", pkgarch:"i586", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
