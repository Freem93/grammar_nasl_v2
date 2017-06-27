#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(80397);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/07 13:49:10 $");

  script_cve_id("CVE-2014-7823");

  script_name(english:"Scientific Linux Security Update : libvirt on SL7.x x86_64");
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
"It was found that when the VIR_DOMAIN_XML_MIGRATABLE flag was used,
the QEMU driver implementation of the virDomainGetXMLDesc() function
could bypass the restrictions of the VIR_DOMAIN_XML_SECURE flag. A
remote attacker able to establish a read-only connection to libvirtd
could use this flaw to leak certain limited information from the
domain XML data. (CVE-2014-7823)

This update also fixes the following bugs :

  - In Scientific Linux 6, libvirt relies on the QEMU
    emulator to supply the error message when an active
    commit is attempted. However, with Scientific Linux 7,
    QEMU added support for an active commit, but an
    additional interaction from libvirt to fully enable
    active commits is still missing. As a consequence,
    attempts to perform an active commit caused libvirt to
    become unresponsive. With this update, libvirt has been
    fixed to detect an active commit by itself, and now
    properly declares the feature as unsupported. As a
    result, libvirt no longer hangs when an active commit is
    attempted and instead produces an error message.

  - Prior to this update, the libvirt API did not properly
    check whether a Discretionary Access Control (DAC)
    security label is non-NULL before trying to parse
    user/group ownership from it. In addition, the DAC
    security label of a transient domain that had just
    finished migrating to another host is in some cases
    NULL. As a consequence, when the virDomainGetBlockInfo
    API was called on such a domain, the libvirtd daemon
    sometimes terminated unexpectedly. With this update,
    libvirt properly checks DAC labels before trying to
    parse them, and libvirtd thus no longer crashes in the
    described scenario.

  - If a block copy operation was attempted while another
    block copy was already in progress to an explicit raw
    destination, libvirt previously stopped regarding the
    destination as raw. As a consequence, if the qemu.conf
    file was edited to allow file format probing, triggering
    the bug could allow a malicious guest to bypass sVirt
    protection by making libvirt regard the file as non-raw.
    With this update, libvirt has been fixed to consistently
    remember when a block copy destination is raw, and
    guests can no longer circumvent sVirt protection when
    the host is configured to allow format probing.

After installing the updated packages, libvirtd will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1501&L=scientific-linux-errata&T=0&P=78
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1008ad1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-client-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-debuginfo-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-devel-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-docs-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-login-shell-1.1.1-29.el7_0.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-python-1.1.1-29.el7_0.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
