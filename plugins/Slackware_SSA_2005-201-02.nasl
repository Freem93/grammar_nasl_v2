#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2005-201-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19851);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:36:13 $");

  script_xref(name:"SSA", value:"2005-201-02");

  script_name(english:"Slackware 10.1 / current : emacs movemail POP utility (SSA:2005-201-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New emacs packages are available for Slackware 10.1 and -current to a
security issue with the movemail utility for retrieving mail from a
POP mail server. If used to connect to a malicious POP server, it is
possible for the server to cause the execution of arbitrary code as
the user running emacs."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.483975
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?168341ea"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:emacs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:emacs-leim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:emacs-lisp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:emacs-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
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
if (slackware_check(osver:"10.1", pkgname:"emacs", pkgver:"21.4a", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"emacs-info", pkgver:"21.4a", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"emacs-leim", pkgver:"21.4", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"emacs-lisp", pkgver:"21.4a", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"emacs-misc", pkgver:"21.4a", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"emacs-nox", pkgver:"21.4a", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"emacs", pkgver:"21.4a", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"emacs-info", pkgver:"21.4a", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"emacs-leim", pkgver:"21.4", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"emacs-lisp", pkgver:"21.4a", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"emacs-misc", pkgver:"21.4a", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"emacs-nox", pkgver:"21.4a", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
