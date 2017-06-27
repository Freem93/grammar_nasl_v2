#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61008);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-3847", "CVE-2011-0536", "CVE-2011-1071", "CVE-2011-1095");

  script_name(english:"Scientific Linux Security Update : glibc on SL5.x,SL6.x i386/x86_64");
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
"The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

The fix for CVE-2010-3847 introduced a regression in the way the
dynamic loader expanded the $ORIGIN dynamic string token specified in
the RPATH and RUNPATH entries in the ELF library header. A local
attacker could use this flaw to escalate their privileges via a setuid
or setgid program using such a library. (CVE-2011-0536)

It was discovered that the glibc fnmatch() function did not properly
restrict the use of alloca(). If the function was called on
sufficiently large inputs, it could cause an application using
fnmatch() to crash or, possibly, execute arbitrary code with the
privileges of the application. (CVE-2011-1071)

It was discovered that the locale command did not produce properly
escaped output as required by the POSIX specification. If an attacker
were able to set the locale environment variables in the environment
of a script that performed shell evaluation on the output of the
locale command, and that script were run with different privileges
than the attacker's, it could execute arbitrary code with the
privileges of the script. (CVE-2011-1095)

All users should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=583
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3000c44"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/04");
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
if (rpm_check(release:"SL5", reference:"glibc-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-common-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-devel-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-headers-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-utils-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"SL5", reference:"nscd-2.5-58.el5_6.2")) flag++;

if (rpm_check(release:"SL6", reference:"glibc-2.12-1.7.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.7.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.7.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.7.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.7.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.7.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.7.el6_0.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
