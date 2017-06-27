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
  script_id(73129);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/04/24 13:06:47 $");

  script_name(english:"SuSE 11.3 Security Update : clamav (SAT Patch Number 9036)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The antivirus scanner ClamAV has been updated to version 0.98.1, which
includes the following fixes :

  - Code quality fixes in libclamav, clamd, sigtool,
    clamav-milter, clamconf, and clamdtop.

  - Code quality fixes in libclamav, libclamunrar and
    freshclam.

  - bb #8385: a PDF ASCII85Decode zero-length fix.

  - bb #7436: elf64 header early exit.

  - libclamav: SCAN_ALL mode fixes.

  - iso9660: iso_scan_file rewrite. Version 0.98.1 also
    implements support for new file types, and quality
    improvements, including Extraction, decompression, and
    scanning of files within the Extensible Archive
    (XAR)/Apple Disk Image (DMG) format, support for
    decompression and scanning of files in the 'Xz'
    compression format.

Additionally, improvements and fixes were done to extraction and
scanning of OLE formats. An option to force all scanned data to disk
was added. Various improvements to ClamAV configuration, support of
third-party libraries, and unit tests were done."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=841815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865883"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9036.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"clamav-0.98.1-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"clamav-0.98.1-0.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"clamav-0.98.1-0.10.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
