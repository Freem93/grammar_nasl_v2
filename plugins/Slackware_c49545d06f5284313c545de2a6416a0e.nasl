#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the associated Slackware Security Advisory. The
# text itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54859);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/01 00:44:11 $");

  script_name(english:"Slackware 8.1 / 9.0 : Mutt buffer overflow in IMAP support");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The mutt mail client packages in Slackware 8.1 and 9.0 have been
upgraded to mutt-1.4.1i to fix a security problem discovered by Core
Security Technologies. This issue may allow a remote attacker
controlling a malicious IMAP server to execute code on your machine as
the user running mutt if you connect to the IMAP server using mutt.
All sites running mutt are advised to upgrade."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.coresecurity.com/common/showdoc.php?idx=310&idxseccion=10"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.273244
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9c6a7e3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mutt package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mutt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"mutt", pkgver:"1.4.1i", pkgarch:"i386", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"mutt", pkgver:"1.4.1i", pkgarch:"i386", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
