#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2003-141-03. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37391);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/01 00:36:12 $");

  script_xref(name:"SSA", value:"2003-141-03");

  script_name(english:"Slackware 8.1 / 9.0 : glibc XDR overflow fix (SSA:2003-141-03)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow in the xdrmem_getbytes() function found in the
glibc library has been fixed. This could allow a remote attacker to
execute arbitrary code by exploiting RPC service that use
xdrmem_getbytes(). None of the default RPC services provided by
Slackware appear to use this function, but third-party applications
may make use of it. We recommend upgrading to these new glibc
packages."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.424088
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfafb927"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-solibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-zoneinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"glibc", pkgver:"2.2.5", pkgarch:"i386", pkgnum:"4")) flag++;
if (slackware_check(osver:"8.1", pkgname:"glibc-solibs", pkgver:"2.2.5", pkgarch:"i386", pkgnum:"4")) flag++;

if (slackware_check(osver:"9.0", pkgname:"glibc", pkgver:"2.3.1", pkgarch:"i386", pkgnum:"4")) flag++;
if (slackware_check(osver:"9.0", pkgname:"glibc-debug", pkgver:"2.3.1", pkgarch:"i386", pkgnum:"4")) flag++;
if (slackware_check(osver:"9.0", pkgname:"glibc-i18n", pkgver:"2.3.1", pkgarch:"noarch", pkgnum:"4")) flag++;
if (slackware_check(osver:"9.0", pkgname:"glibc-profile", pkgver:"2.3.1", pkgarch:"i386", pkgnum:"4")) flag++;
if (slackware_check(osver:"9.0", pkgname:"glibc-solibs", pkgver:"2.3.1", pkgarch:"i386", pkgnum:"4")) flag++;
if (slackware_check(osver:"9.0", pkgname:"glibc-zoneinfo", pkgver:"2.3.1", pkgarch:"noarch", pkgnum:"4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
