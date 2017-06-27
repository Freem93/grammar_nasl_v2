#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(72210);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/30 11:50:28 $");

  script_cve_id("CVE-2013-4494");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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
"  - It was found that the Xen hypervisor did not always lock
    'page_alloc_lock' and 'grant_table.lock' in the same
    order. This could potentially lead to a deadlock. A
    malicious guest administrator could use this flaw to
    cause a denial of service on the host. (CVE-2013-4494,
    Moderate)

This update also fixes the following bugs :

  - A recent patch to the CIFS code that introduced the
    NTLMSSP (NT LAN Manager Security Support Provider)
    authentication mechanism caused a regression in CIFS
    behavior. As a result of the regression, an encryption
    key that is returned during the SMB negotiation protocol
    response was only used for the first session that was
    created on the SMB client. Any subsequent mounts to the
    same server did not use the encryption key returned by
    the initial negotiation with the server. As a
    consequence, it was impossible to mount multiple SMB
    shares with different credentials to the same server. A
    patch has been applied to correct this problem so that
    an encryption key or a server challenge is now provided
    for every SMB session during the SMB negotiation
    protocol response.

  - The igb driver previously used a 16-bit mask when
    writing values of the flow control high-water mark to
    hardware registers on a network device. Consequently,
    the values were truncated on some network devices,
    disrupting the flow control. A patch has been applied to
    the igb driver so that it now uses a 32-bit mask as
    expected.

  - The IPMI driver did not properly handle kernel panic
    messages. Consequently, when a kernel panic occurred on
    a system that was utilizing IPMI without Kdump being set
    up, a second kernel panic could be triggered. A patch
    has been applied to the IPMI driver to fix this problem,
    and a message handler now properly waits for a response
    to panic event messages.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1401&L=scientific-linux-errata&T=0&P=1481
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8cb96d26"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-371.4.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-371.4.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
