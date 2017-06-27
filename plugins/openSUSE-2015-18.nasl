#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-18.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80543);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2014-9496");
  script_osvdb_id(116355);

  script_name(english:"openSUSE Security Update : libsndfile (openSUSE-SU-2015:0041-1)");
  script_summary(english:"Check for the openSUSE-2015-18 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in libsndfile: two buffer read overflows in
sd2_parse_rsrc_fork() (CVE-2014-9496, bnc#911796): backported upstream
fix patches"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-01/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911796"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsndfile packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-debugsource-1.0.25-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-devel-1.0.25-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-progs-1.0.25-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-progs-debuginfo-1.0.25-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile-progs-debugsource-1.0.25-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile1-1.0.25-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsndfile1-debuginfo-1.0.25-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsndfile1-32bit-1.0.25-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsndfile1-debuginfo-32bit-1.0.25-17.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-debugsource-1.0.25-19.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-devel-1.0.25-19.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-progs-1.0.25-19.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-progs-debuginfo-1.0.25-19.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile-progs-debugsource-1.0.25-19.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile1-1.0.25-19.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsndfile1-debuginfo-1.0.25-19.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsndfile1-32bit-1.0.25-19.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsndfile1-debuginfo-32bit-1.0.25-19.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsndfile-progs / libsndfile-progs-debuginfo / etc");
}
