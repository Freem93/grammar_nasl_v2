#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65092);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/08 11:44:06 $");

  script_cve_id("CVE-2012-6075");

  script_name(english:"Scientific Linux Security Update : qemu-kvm on SL6.x i386/x86_64");
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
"A flaw was found in the way QEMU-KVM emulated the e1000 network
interface card when the host was configured to accept jumbo network
frames, and a guest using the e1000 emulated driver was not. A remote
attacker could use this flaw to crash the guest or, potentially,
execute arbitrary code with root privileges in the guest.
(CVE-2012-6075)

After installing this update, shut down all running virtual machines.
Once all virtual machines have shut down, start them again for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=3090
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8cd2861f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/08");
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
if (rpm_check(release:"SL6", reference:"qemu-guest-agent-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-guest-agent-win32-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"qemu-kvm-debuginfo-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"seabios-0.6.1.2-26.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-glib-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-glib-devel-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-devel-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-python-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-tools-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-protocol-0.12.2-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"spice-server-0.12.0-12.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"spice-server-devel-0.12.0-12.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-vdagent-0.12.0-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-xpi-2.7-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"usbredir-0.5.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"usbredir-devel-0.5.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"usbredir-server-0.5.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"virt-viewer-0.5.2-18.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");