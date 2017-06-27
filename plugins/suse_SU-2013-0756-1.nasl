#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:0756-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83582);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2012-3438");
  script_bugtraq_id(54716);

  script_name(english:"SUSE SLED10 Security Update : ImageMagick (SUSE-SU-2013:0756-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ImageMagick has been updated to fix an integer overflow
(CVE-2012-3438).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=197e00af8ca9eee4ffb65e54b040e40d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c47e1ef"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/773612"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20130756-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15cfca2b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-Magick++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"ImageMagick-6.2.5-16.36.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"ImageMagick-Magick++-6.2.5-16.36.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"ImageMagick-devel-6.2.5-16.36.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"perl-PerlMagick-6.2.5-16.36.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"ImageMagick-6.2.5-16.36.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"ImageMagick-Magick++-6.2.5-16.36.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"ImageMagick-devel-6.2.5-16.36.2")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"perl-PerlMagick-6.2.5-16.36.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
