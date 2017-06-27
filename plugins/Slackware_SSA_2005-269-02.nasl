#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2005-269-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19867);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/01 00:36:13 $");

  script_cve_id("CVE-2005-2495");
  script_osvdb_id(19352);
  script_xref(name:"SSA", value:"2005-269-02");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / current : X.Org pixmap overflow (SSA:2005-269-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New X.Org server packages are available for Slackware 10.0, 10.1,
10.2, and -current to fix a security issue. An integer overflow in the
pixmap handling code may allow the execution of arbitrary code through
a specially crafted pixmap. Slackware 10.2 was patched against this
vulnerability before its release, but new server packages are being
issued for Slackware 10.2 and -current using an improved patch, as
there were some bug reports using certain programs."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.586951
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9018ea5f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xprt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:x11-xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/13");
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
if (slackware_check(osver:"10.0", pkgname:"x11", pkgver:"6.7.0", pkgarch:"i486", pkgnum:"5")) flag++;
if (slackware_check(osver:"10.0", pkgname:"x11-xnest", pkgver:"6.7.0", pkgarch:"i486", pkgnum:"5")) flag++;
if (slackware_check(osver:"10.0", pkgname:"x11-xprt", pkgver:"6.7.0", pkgarch:"i486", pkgnum:"5")) flag++;
if (slackware_check(osver:"10.0", pkgname:"x11-xvfb", pkgver:"6.7.0", pkgarch:"i486", pkgnum:"5")) flag++;

if (slackware_check(osver:"10.1", pkgname:"x11", pkgver:"6.8.1", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"10.1", pkgname:"x11-xdmx", pkgver:"6.8.1", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"10.1", pkgname:"x11-xnest", pkgver:"6.8.1", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"10.1", pkgname:"x11-xvfb", pkgver:"6.8.1", pkgarch:"i486", pkgnum:"4")) flag++;

if (slackware_check(osver:"10.2", pkgname:"x11", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-xdmx", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-xnest", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"10.2", pkgname:"x11-xvfb", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"4")) flag++;

if (slackware_check(osver:"current", pkgname:"x11", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-xdmx", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-xnest", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"4")) flag++;
if (slackware_check(osver:"current", pkgname:"x11-xvfb", pkgver:"6.8.2", pkgarch:"i486", pkgnum:"4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
