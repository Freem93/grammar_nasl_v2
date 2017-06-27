#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61247);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_name(english:"Scientific Linux Security Update : selinux-policy on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The selinux-policy packages contain the rules that govern how confined
processes run on the system.

This update fixes the following bug :

  - An incorrect SELinux policy prevented the qpidd service
    from starting. These selinux-policy packages contain
    updated SELinux rules, which allow the qpidd service to
    be started correctly.

  - With SELinux in enforcing mode, the ssh-keygen utility
    was prevented from access to various applications and
    thus could not be used to generate SSH keys for these
    programs. With this update, the 'ssh_keygen_t' SELinux
    domain type has been implemented as unconfined, which
    ensures the ssh-keygen utility to work correctly.

All users of selinux-policy are advised to upgrade to these updated
packages, which fix these bugs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=2091
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a57f3f0a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"selinux-policy-3.7.19-126.el6_2.6")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-doc-3.7.19-126.el6_2.6")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-minimum-3.7.19-126.el6_2.6")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-mls-3.7.19-126.el6_2.6")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-targeted-3.7.19-126.el6_2.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
