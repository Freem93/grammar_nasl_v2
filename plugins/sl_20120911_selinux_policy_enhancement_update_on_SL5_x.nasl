#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62059);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/09/12 19:23:50 $");

  script_name(english:"Scientific Linux Security Update : selinux-policy enhancement update on SL5.x, SL6.x i386/x86_64");
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
"This update adds the following enhancements :

  - Previously, with the MLS policy activated, a user
    created with a MLS level was not able to log into the
    system using the ssh utility because an appropriate MLS
    policy rule was missing. This update adds the MLS rule
    and users can now log into the system as expected in the
    described scenario.

  - When OpenMPI (Open Message Passing Interface) was
    configured to use the parallel universe environment in
    the Condor server, a large number of AVC messages was
    returned when an OpenMPI job was submitted.
    Consequently, the job failed. This update fixes the
    appropriate SELinux policy and OpenMPI jobs now pass
    successfully and no longer cause AVC messages to be
    returned.

This update has been placed in the security tree to avoid selinux
bugs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=1083
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94b3b0b2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/12");
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
if (rpm_check(release:"SL6", reference:"selinux-policy-3.7.19-155.el6_3.4")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-doc-3.7.19-155.el6_3.4")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-minimum-3.7.19-155.el6_3.4")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-mls-3.7.19-155.el6_3.4")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-targeted-3.7.19-155.el6_3.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
