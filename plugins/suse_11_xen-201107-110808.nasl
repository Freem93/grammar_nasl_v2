#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55973);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2011-1898");

  script_name(english:"SuSE 11.1 Security Update : Xen (SAT Patch Number 4977)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security / Collective Update for Xen

Xen :

  - VUL-0: xen: VT-d (PCI passthrough) MSI trap injection.
    (CVE-2011-1898). (bnc#702025)

  - update block-npiv scripts to support BFA HBA.
    (bnc#703924)

  - L3: Live migrations fail when guest crashes:
    domain_crash_sync called from entry.S. (bnc#689954)

  - Bridge hangs cause redundant ring failures in SLE 11 SP1
    HAE + XEN. (bnc#693472)

  - xen-scsi.ko not supported. (bnc#582265)

  - When connecting to Xen guest through vncviewer mouse
    tracking is off. (bnc#670465)

  - on_crash is being ignored with kdump now working in HVM.
    (bnc#684305)

  - HVM taking too long to dump vmcore. (bnc#684297)

  - crm resource migrate fails with xen machines.
    (bnc#704160)

  - xm console DomUName hang after 'xm save/restore' of PVM
    on the latest Xen vm-install:. (bnc#706574)

  - virt-manager has problems to install guest from multiple
    CD. (bnc#692625)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=582265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=684297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=684305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=692625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=693472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=702025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=703924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=706574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1898.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4977.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:vm-install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"vm-install-0.4.31-0.3.5")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-kmp-default-4.0.2_21511_02_2.6.32.43_0.4-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-kmp-pae-4.0.2_21511_02_2.6.32.43_0.4-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-libs-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-tools-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-tools-domU-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"vm-install-0.4.31-0.3.5")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-kmp-default-4.0.2_21511_02_2.6.32.43_0.4-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-libs-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-tools-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-tools-domU-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"vm-install-0.4.31-0.3.5")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-doc-html-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-doc-pdf-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-kmp-default-4.0.2_21511_02_2.6.32.43_0.4-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-kmp-pae-4.0.2_21511_02_2.6.32.43_0.4-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-libs-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-tools-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-tools-domU-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"vm-install-0.4.31-0.3.5")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-doc-html-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-doc-pdf-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-kmp-default-4.0.2_21511_02_2.6.32.43_0.4-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-libs-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-tools-4.0.2_21511_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-tools-domU-4.0.2_21511_02-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
