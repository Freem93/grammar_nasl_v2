#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65016);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2013-0219", "CVE-2013-0220");

  script_name(english:"Scientific Linux Security Update : sssd on SL6.x i386/x86_64");
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
"A race condition was found in the way SSSD copied and removed user
home directories. A local attacker who is able to write into the home
directory of a different user who is being removed could use this flaw
to perform symbolic link attacks, possibly allowing them to modify and
delete arbitrary files with the privileges of the root user.
(CVE-2013-0219)

Multiple out-of-bounds memory read flaws were found in the way the
autofs and SSH service responders parsed certain SSSD packets. An
attacker could spend a specially crafted packet that, when processed
by the autofs or SSH service responders, would cause SSSD to crash.
This issue only caused a temporary denial of service, as SSSD was
automatically restarted by the monitor process after the crash.
(CVE-2013-0220)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=579
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91dad60c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libipa_hbac-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libipa_hbac-devel-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libipa_hbac-python-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_autofs-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_idmap-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_idmap-devel-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_sudo-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_sudo-devel-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-client-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-debuginfo-1.9.2-82.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-tools-1.9.2-82.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
