#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0008.
#

include("compat.inc");

if (description)
{
  script_id(79497);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/03 14:49:09 $");

  script_cve_id("CVE-2012-4398", "CVE-2012-4461", "CVE-2012-4530", "CVE-2013-0190", "CVE-2013-0231");
  script_bugtraq_id(55361, 55878, 56414, 57433, 57740);
  script_osvdb_id(85718, 86575);

  script_name(english:"OracleVM 3.2 : kernel-uek (OVMSA-2013-0008)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - kmod: make __request_module killable (Oleg Nesterov)
    [Orabug: 16286305] (CVE-2012-4398)

  - kmod: introduce call_modprobe helper (Oleg Nesterov)
    [Orabug: 16286305] (CVE-2012-4398)

  - usermodehelper: implement UMH_KILLABLE (Oleg Nesterov)
    [Orabug: 16286305] (CVE-2012-4398)

  - usermodehelper: introduce umh_complete(sub_info) (Oleg
    Nesterov) [Orabug: 16286305] (CVE-2012-4398)

  - KVM: x86: invalid opcode oops on SET_SREGS with OSXSAVE
    bit set (CVE-2012-4461) (Jerry Snitselaar) [Orabug:
    16286290] (CVE-2012-4461)

  - exec: do not leave bprm->interp on stack (Kees Cook)
    [Orabug: 16286267] (CVE-2012-4530)

  - exec: use -ELOOP for max recursion depth (Kees Cook)
    [Orabug: 16286267] (CVE-2012-4530)

  - xen-pciback: rate limit error messages from
    xen_pcibk_enable_msi[,x] (Jan Beulich) [Orabug:
    16243736] (CVE-2013-0231)

  - Xen: Fix stack corruption in xen_failsafe_callback for
    32bit PVOPS guests. (Frediano Ziglio) [Orabug: 16274171]
    (CVE-2013-0190)

  - netback: correct netbk_tx_err to handle wrap around.
    (Ian Campbell) [Orabug: 16243309]

  - xen/netback: free already allocated memory on failure in
    xen_netbk_get_requests (Ian Campbell) [Orabug: 16243309]

  - xen/netback: don't leak pages on failure in
    xen_netbk_tx_check_gop. (Ian Campbell) [Orabug:
    16243309]

  - xen/netback: shutdown the ring if it contains garbage.
    (Ian Campbell) [Orabug: 16243309]

  - ixgbevf fix typo in Makefile (Maxim Uvarov) [Orabug:
    16179639 16168292]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-February/000123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cae6ceac"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-2.6.39-300.28.1.el5uek")) flag++;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-firmware-2.6.39-300.28.1.el5uek")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
