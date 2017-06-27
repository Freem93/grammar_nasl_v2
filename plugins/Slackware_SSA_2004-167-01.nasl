#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2004-167-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18791);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/01 00:36:12 $");

  script_cve_id("CVE-2004-0554");
  script_osvdb_id(7077);
  script_xref(name:"SSA", value:"2004-167-01");

  script_name(english:"Slackware 8.1 / 9.0 / 9.1 / current : kernel DoS (SSA:2004-167-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New kernel packages are available for Slackware 8.1, 9.0, 9.1, and
-current to fix a denial of service security issue. Without a patch to
asm-i386/i387.h, a local user can crash the machine."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.612137
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3a10acd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-ide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/16");
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
if (slackware_check(osver:"8.1", pkgname:"kernel-ide", pkgver:"2.4.18", pkgarch:"i386", pkgnum:"6")) flag++;
if (slackware_check(osver:"8.1", pkgname:"kernel-source", pkgver:"2.4.18", pkgarch:"noarch", pkgnum:"7")) flag++;

if (slackware_check(osver:"9.0", pkgname:"kernel-ide", pkgver:"2.4.21", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"9.0", pkgname:"kernel-source", pkgver:"2.4.21", pkgarch:"noarch", pkgnum:"4")) flag++;

if (slackware_check(osver:"9.1", pkgname:"kernel-ide", pkgver:"2.4.26", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"9.1", pkgname:"kernel-source", pkgver:"2.4.26", pkgarch:"noarch", pkgnum:"2")) flag++;

if (slackware_check(osver:"current", pkgname:"kernel-generic", pkgver:"2.6.6", pkgarch:"i486", pkgnum:"5")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-headers", pkgver:"2.4.26", pkgarch:"i386", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-ide", pkgver:"2.4.26", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-source", pkgver:"2.4.26", pkgarch:"noarch", pkgnum:"4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:slackware_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
