#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-130-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21346);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/07/20 01:56:57 $");

  script_cve_id("CVE-2005-3352");
  script_xref(name:"SSA", value:"2006-130-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 8.1 / 9.0 / 9.1 / current : Apache httpd redux (SSA:2006-130-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Apache packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, 10.2, and -current to fix a bug with Apache 1.3.35 and glibc
that breaks wildcards in Include directives. It may not occur with all
versions of glibc, but it has been verified on -current (using an
Include within a file already Included causes a crash), so better to
patch it and reissue these packages just to be sure. My apologies if
the last batch of updates caused anyone undue grief... they worked
here with my (too simple?) config files. Note that if you use mod_ssl,
you'll also require the mod_ssl package that was part of yesterday's
release, and on -current you'll need the newest PHP package (if you
use PHP). Thanks to Francesco Gringoli for bringing this issue to my
attention."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.470158
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?269cdf3c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"apache", pkgver:"1.3.35", pkgarch:"i386", pkgnum:"2_slack8.1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"apache", pkgver:"1.3.35", pkgarch:"i386", pkgnum:"2_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"apache", pkgver:"1.3.35", pkgarch:"i486", pkgnum:"2_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"apache", pkgver:"1.3.35", pkgarch:"i486", pkgnum:"2_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"apache", pkgver:"1.3.35", pkgarch:"i486", pkgnum:"2_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"apache", pkgver:"1.3.35", pkgarch:"i486", pkgnum:"2_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"apache", pkgver:"1.3.35", pkgarch:"i486", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
