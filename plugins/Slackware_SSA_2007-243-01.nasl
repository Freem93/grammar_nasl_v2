#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2007-243-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25957);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/19 15:18:22 $");

  script_cve_id("CVE-2007-3922");
  script_bugtraq_id(22085, 24004, 24846);
  script_osvdb_id(32834, 36199, 36200, 36201, 36202, 36488, 36662, 36663);
  script_xref(name:"SSA", value:"2007-243-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 / 12.0 / 8.1 / 9.0 / 9.1 : java (jre, jdk) (SSA:2007-243-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun has released security advisories pertaining to both the Java
Runtime Environment and the Standard Edition Development Kit. One such
advisory may be found here:
http://sunsolve.sun.com/search/document.do?assetkey=1-26-102995-1
Updated versions of both the jre and jdk packages are provided which
address all known flaws in Java(TM) at this time. There may be more
advisories on http://sunsolve.sun.com describing other flaws that are
patched with this update. Happy hunting! Slackware repackages Sun's
Java(TM) binaries without changing them, so the packages from
Slackware 12.0 should work on all glibc based Slackware versions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102995-1"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.486841
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31748020"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jdk and / or jre packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"jdk", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"8.1", pkgname:"jre", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"jdk", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.0", pkgname:"jre", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.1", pkgname:"jdk", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"jre", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"jdk", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.0", pkgname:"jre", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.1", pkgname:"jdk", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"jre", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"jdk", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.2", pkgname:"jre", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"11.0", pkgname:"jdk", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"11.0", pkgname:"jre", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;

if (slackware_check(osver:"12.0", pkgname:"jdk", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"12.0", pkgname:"jre", pkgver:"6u2", pkgarch:"i586", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
