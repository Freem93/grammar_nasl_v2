#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61185);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/11 10:47:29 $");

  script_cve_id("CVE-2011-1020", "CVE-2011-3347", "CVE-2011-3638", "CVE-2011-4110");

  script_name(english:"Scientific Linux Security Update : Scientific Linux 6 kernel on SL6.x i386/x86_64");
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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

  - The proc file system could allow a local, unprivileged
    user to obtain sensitive information or possibly cause
    integrity issues. (CVE-2011-1020, Moderate)

  - Non-member VLAN (virtual LAN) packet handling for
    interfaces in promiscuous mode and also using the be2net
    driver could allow an attacker on the local network to
    cause a denial of service. (CVE-2011-3347, Moderate)

  - A flaw was found in the Linux kernel in the way
    splitting two extents in
    ext4_ext_convert_to_initialized() worked. A local,
    unprivileged user with access to mount and unmount ext4
    file systems could use this flaw to cause a denial of
    service. (CVE-2011-3638, Moderate)

  - A NULL pointer dereference flaw was found in the way the
    Linux kernel's key management facility handled
    user-defined key types. A local, unprivileged user could
    use the keyctl utility to cause a denial of service.
    (CVE-2011-4110, Moderate)

This update also fixes several hundred bugs and adds enhancements.
Refer to the upstream Release Notes for information on the most
significant of these changes.

All Scientific Linux 6 users are advised to install these updated
packages, which correct these issues, and fix the bugs and add the
enhancements noted. The system must be rebooted for this update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=4161
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c44d07a4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-220.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-220.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
