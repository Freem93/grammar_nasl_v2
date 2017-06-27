#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60959);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-4527", "CVE-2010-4655", "CVE-2011-0521");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
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
"This update fixes the following security issues :

  - A buffer overflow flaw was found in the
    load_mixer_volumes() function in the Linux kernel's Open
    Sound System (OSS) sound driver. On 64-bit PowerPC
    systems, a local, unprivileged user could use this flaw
    to cause a denial of service or escalate their
    privileges. (CVE-2010-4527, Important)

  - A missing boundary check was found in the dvb_ca_ioctl()
    function in the Linux kernel's av7110 module. On systems
    that use old DVB cards that require the av7110 module, a
    local, unprivileged user could use this flaw to cause a
    denial of service or escalate their privileges.
    (CVE-2011-0521, Important)

  - A missing initialization flaw was found in the
    ethtool_get_regs() function in the Linux kernel's
    ethtool IOCTL handler. A local user who has the
    CAP_NET_ADMIN capability could use this flaw to cause an
    information leak. (CVE-2010-4655, Low)

These updated kernel packages also fix hundreds of bugs and add
numerous enhancements.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=3646
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6305d50c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-utils-2.4-23.el4")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-100.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-100.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
