#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1045-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84190);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2015-3209", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-4163", "CVE-2015-4164");
  script_bugtraq_id(74947, 74948, 74949, 74950, 75123, 75141, 75149);
  script_osvdb_id(122855, 122856, 122857, 122858, 123147, 123237, 123281);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : Xen (SUSE-SU-2015:1045-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xen was updated to fix seven security vulnerabilities :

CVE-2015-4103: Potential unintended writes to host MSI message data
field via qemu. (XSA-128, bnc#931625)

CVE-2015-4104: PCI MSI mask bits inadvertently exposed to guests.
(XSA-129, bnc#931626)

CVE-2015-4105: Guest triggerable qemu MSI-X pass-through error
messages. (XSA-130, bnc#931627)

CVE-2015-4106: Unmediated PCI register access in qemu. (XSA-131,
bnc#931628)

CVE-2015-4163: GNTTABOP_swap_grant_ref operation misbehavior.
(XSA-134, bnc#932790)

CVE-2015-3209: Heap overflow in qemu pcnet controller allowing guest
to host escape. (XSA-135, bnc#932770)

CVE-2015-4164: DoS through iret hypercall handler. (XSA-136,
bnc#932996)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932996"
  );
  # https://download.suse.com/patch/finder/?keywords=3ae6793ddbacaa600cc65649e1e37a48
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0950fd72"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3209.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4103.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4164.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151045-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f488f66"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-xen-201506=10727

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-xen-201506=10727

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-xen-201506=10727

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-libs-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-tools-domU-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-libs-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-tools-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-libs-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-tools-domU-4.2.5_08-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
