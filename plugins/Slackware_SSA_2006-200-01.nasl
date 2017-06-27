#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-200-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22081);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:36:13 $");

  script_xref(name:"SSA", value:"2006-200-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / current : Samba 2.0.23 repackaged (SSA:2006-200-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Samba packages are available for Slackware 10.0, 10.1, 10.2, and
-current. In Slackware 10.0, 10.1, and 10.2, Samba was evidently
picking up the libdm.so.0 library causing a Samba package issued
primarily as a security patch to suddenly require a library that would
only be present on the machine if the xfsprogs package (from the A
series but marked 'optional') was installed. Sorry -- this was not
intentional, though I do know that I'm taking the chance of this kind
of issue when trying to get security related problems fixed quickly
(hopefully balanced with reasonable testing), and when the fix is
achieved by upgrading to a new version rather than with the smallest
patch possible to fix the known issue. However, I tend to trust that
by following upstream sources as much as possible I'm also fixing some
problems that aren't yet public. So, all of the the 10.0, 10.1, and
10.2 packages have been rebuilt on systems without the dm library, and
should be able to directly upgrade older samba packages without
additional requirements. Well, unless they are also under /patches.
;-) All the packages (including -current) have been patched with a fix
from Samba's CVS for some reported problems with winbind. Thanks to
Mikhail Kshevetskiy for pointing me to the patch. I realize these
packages don't really fix security issues, but they do fix security
patch packages that are less than a couple of days old, so it seems
prudent to notify slackware-security (and any subscribed lists) again.
Sorry if it's noise..."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.544288
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8f00849"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected samba package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/20");
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
if (slackware_check(osver:"10.0", pkgname:"samba", pkgver:"3.0.23", pkgarch:"i486", pkgnum:"2_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"samba", pkgver:"3.0.23", pkgarch:"i486", pkgnum:"2_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"samba", pkgver:"3.0.23", pkgarch:"i486", pkgnum:"2_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"samba", pkgver:"3.0.23", pkgarch:"i486", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
