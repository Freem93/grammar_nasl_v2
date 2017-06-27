#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60891);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/08/16 16:01:59 $");

  script_cve_id("CVE-2010-3847", "CVE-2010-3856");

  script_name(english:"Scientific Linux Security Update : glibc on SL6.x i386/x86_64");
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
"It was discovered that the glibc dynamic linker/loader did not handle
the $ORIGIN dynamic string token set in the LD_AUDIT environment
variable securely. A local attacker with write access to a file system
containing setuid or setgid binaries could use this flaw to escalate
their privileges. (CVE-2010-3847)

It was discovered that the glibc dynamic linker/loader did not perform
sufficient safety checks when loading dynamic shared objects (DSOs) to
provide callbacks for its auditing API during the execution of
privileged programs. A local attacker could use this flaw to escalate
their privileges via a carefully-chosen system DSO library containing
unsafe constructors. (CVE-2010-3856)

This update also fixes the following bugs :

  - Previously, the generic implementation of the strstr()
    and memmem() functions did not handle certain periodic
    patterns correctly and could find a false positive
    match. This error has been fixed, and both functions now
    work as expected. (BZ#643341)

  - The 'TCB_ALIGNMENT' value has been increased to 32 bytes
    to prevent applications from crashing during symbol
    resolution on 64-bit systems with support for Intel AVX
    vector registers. (BZ#643343)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=1851
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5cc6ce9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=643341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=643343"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"glibc-2.12-1.7.el6_0.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.7.el6_0.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.7.el6_0.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.7.el6_0.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.7.el6_0.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.7.el6_0.3")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.7.el6_0.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
