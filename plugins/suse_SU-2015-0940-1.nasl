#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0940-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83856);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2015-3340", "CVE-2015-3456");
  script_bugtraq_id(74248, 74640);
  script_osvdb_id(121091, 122072);

  script_name(english:"SUSE SLES11 Security Update : Xen (SUSE-SU-2015:0940-1) (Venom)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xen was updated to fix two security issues :

CVE-2015-3456: A buffer overflow in the floppy drive emulation, which
could be used to carry out denial of service attacks or potential code
execution against the host. This vulnerability is also known as VENOM.

CVE-2015-3340: An information leak through XEN_DOMCTL_gettscinfo().
(XSA-132)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929339"
  );
  # https://download.suse.com/patch/finder/?keywords=aee7c643a4c4513e4350b80ada2e9e6f
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7ed16c6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3340.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3456.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150940-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78ddef52"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-xen=10684

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/27");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-doc-html-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-doc-pdf-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.0.3_21548_18_2.6.32.59_0.19-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-trace-4.0.3_21548_18_2.6.32.59_0.19-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-libs-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-tools-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-tools-domU-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"xen-kmp-pae-4.0.3_21548_18_2.6.32.59_0.19-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-doc-html-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-doc-pdf-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-default-4.0.3_21548_18_2.6.32.59_0.19-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-trace-4.0.3_21548_18_2.6.32.59_0.19-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-libs-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-tools-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-tools-domU-4.0.3_21548_18-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"i586", reference:"xen-kmp-pae-4.0.3_21548_18_2.6.32.59_0.19-0.21.1")) flag++;


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
