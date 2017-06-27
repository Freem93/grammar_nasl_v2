#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(69796);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/02 10:37:33 $");

  script_cve_id("CVE-2013-4169");

  script_name(english:"Scientific Linux Security Update : gdm on SL5.x i386/srpm/x86_64");
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
"A race condition was found in the way GDM handled the X server sockets
directory located in the system temporary directory. An unprivileged
user could use this flaw to perform a symbolic link attack, giving
them write access to any file, allowing them to escalate their
privileges to root. (CVE-2013-4169)

Note that this erratum includes an updated initscripts package. To fix
CVE-2013-4169, the vulnerable code was removed from GDM and the
initscripts package was modified to create the affected directory
safely during the system boot process. Therefore, this update will
appear on all systems, however systems without GDM installed are not
affected by this flaw.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1309&L=scientific-linux-errata&T=0&P=320
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3215dcc2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/06");
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
if (rpm_check(release:"SL5", reference:"gdm-2.16.0-59.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"gdm-debuginfo-2.16.0-59.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"gdm-debuginfo-2.16.0-59.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"gdm-docs-2.16.0-59.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"initscripts-8.45.42-2.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"initscripts-debuginfo-8.45.42-2.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"initscripts-debuginfo-8.45.42-2.el5_9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
