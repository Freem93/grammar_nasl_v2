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
  script_id(82641);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/08 13:41:02 $");

  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");

  script_name(english:"SuSE 11.3 Security Update : xorg-x11-libs (SAT Patch Number 10487)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibXFont was updated to fix security problems that could be used by
local attackers to gain X server privileges (root).

The following security issues have been fixed :

  - The bdf parser reads a count for the number of
    properties defined in a font from the font file, and
    allocates arrays with entries for each property based on
    that count. It never checked to see if that count was
    negative, or large enough to overflow when multiplied by
    the size of the structures being allocated, and could
    thus allocate the wrong buffer size, leading to out of
    bounds writes. (CVE-2015-1802)

  - If the bdf parser failed to parse the data for the
    bitmap for any character, it would proceed with an
    invalid pointer to the bitmap data and later crash when
    trying to read the bitmap from that pointer.
    (CVE-2015-1803)

  - The bdf parser read metrics values as 32-bit integers,
    but stored them into 16-bit integers. Overflows could
    occur in various operations leading to out-of-bounds
    memory access. (CVE-2015-1804)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=921978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-1802.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-1803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-1804.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10487.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xorg-x11-libs-7.4-8.26.44.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xorg-x11-libs-7.4-8.26.44.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xorg-x11-libs-32bit-7.4-8.26.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"xorg-x11-libs-7.4-8.26.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"xorg-x11-libs-32bit-7.4-8.26.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xorg-x11-libs-32bit-7.4-8.26.44.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
