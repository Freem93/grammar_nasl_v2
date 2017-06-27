#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60852);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-2059");

  script_name(english:"Scientific Linux Security Update : rpm on SL5.x i386/x86_64");
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
"It was discovered that RPM did not remove setuid and setgid bits set
on binaries when upgrading packages. A local attacker able to create
hard links to binaries could use this flaw to keep those binaries on
the system, at a specific version level and with the setuid or setgid
bit set, even if the package providing them was upgraded by a system
administrator. This could have security implications if a package was
upgraded because of a security flaw in a setuid or setgid program.
(CVE-2010-2059)

This update also fixes the following bug :

  - A memory leak in the communication between RPM and the
    Security-Enhanced Linux (SELinux) subsystem, which could
    have caused extensive memory consumption. In reported
    cases, this issue was triggered by running rhn_check
    when errata were scheduled to be applied. (BZ#627630)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1009&L=scientific-linux-errata&T=0&P=327
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78b44a8f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=627630"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/07");
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
if (rpm_check(release:"SL5", reference:"popt-1.10.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-apidocs-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-build-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-devel-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-libs-4.4.2.3-20.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"rpm-python-4.4.2.3-20.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
