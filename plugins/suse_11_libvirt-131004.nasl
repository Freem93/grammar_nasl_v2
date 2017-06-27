#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(70797);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/11/09 16:08:20 $");

  script_cve_id("CVE-2013-4291", "CVE-2013-4296", "CVE-2013-4311", "CVE-2013-5651");

  script_name(english:"SuSE 11.3 Security Update : libvirt (SAT Patch Number 8421)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libvirt has been updated to the 1.0.5.6 stable release that fixes bugs
and security issues :

  - Fix crash in remoteDispatchDomainMemoryStats.
    (CVE-2013-4296)

  - virBitmapParse out-of-bounds read access Libvirt on SLES
    11 SP3 is not affected:. (CVE-2013-5651)

  - Add support for using 3-arg pkcheck syntax for process
    (). (CVE-2013-4311)

  - security: provide supplemental groups even when parsing
    label () Changes in this version:. (CVE-2013-4291)

  - virsh: fix change-media bug on disk block type

  - Include process start time when doing polkit checks

  - qemuDomainChangeGraphics: Check listen address change by
    listen type

  - python: return dictionary without value in case of no
    blockjob

  - virbitmap: Refactor virBitmapParse to avoid access
    beyond bounds of array Also the following bug has been
    fixed :

  - Fix retrieval of SRIOV VF info, which prevented using
    some SRIOV virtual functions in guest domains with ''
    (bnc#837329)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=838638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4291.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5651.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8421.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libvirt-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libvirt-client-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libvirt-doc-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libvirt-python-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libvirt-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libvirt-client-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libvirt-client-32bit-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libvirt-doc-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libvirt-python-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libvirt-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libvirt-client-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libvirt-doc-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libvirt-lock-sanlock-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libvirt-python-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libvirt-client-32bit-1.0.5.6-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libvirt-client-32bit-1.0.5.6-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
