#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(66491);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/05/30 10:47:59 $");

  script_cve_id("CVE-2013-1962");

  script_name(english:"Scientific Linux Security Update : libvirt on SL6.x i386/x86_64");
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
"It was found that libvirtd leaked file descriptors when listing all
volumes for a particular pool. A remote attacker able to establish a
read- only connection to libvirtd could use this flaw to cause
libvirtd to consume all available file descriptors, preventing other
users from using libvirtd services (such as starting a new guest)
until libvirtd is restarted. (CVE-2013-1962)

This update also fixes the following bugs :

  - Previously, libvirt made control group (cgroup) requests
    on files that it should not have. With older kernels,
    such nonsensical cgroup requests were ignored; however,
    newer kernels are stricter, resulting in libvirt logging
    spurious warnings and failures to the libvirtd and audit
    logs. The audit log failures displayed by the ausearch
    tool were similar to the following :

root [date] - failed cgroup allow path rw /dev/kqemu

With this update, libvirt no longer attempts the nonsensical cgroup
actions, leaving only valid attempts in the libvirtd and audit logs
(making it easier to search for real cases of failure).

  - Previously, libvirt used the wrong variable when
    constructing audit messages. This led to invalid audit
    messages, causing ausearch to format certain entries as
    having 'path=(null)' instead of the correct path. This
    could prevent ausearch from locating events related to
    cgroup device ACL modifications for guests managed by
    libvirt. With this update, the audit messages are
    generated correctly, preventing loss of audit coverage.

After installing the updated packages, libvirtd will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1305&L=scientific-linux-errata&T=0&P=1195
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e36d8b86"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libvirt-0.10.2-18.el6_4.5")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-client-0.10.2-18.el6_4.5")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-debuginfo-0.10.2-18.el6_4.5")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-devel-0.10.2-18.el6_4.5")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-18.el6_4.5")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-python-0.10.2-18.el6_4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
