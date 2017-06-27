#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-722.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75153);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-0252");

  script_name(english:"openSUSE Security Update : boost (openSUSE-SU-2013:1523-1)");
  script_summary(english:"Check for the openSUSE-2013-722 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This boost update fixes a UTF validation problem.

  - Apply boost-locale_utf.patch to fix a vulnerability in
    the utf handling of boost:locale (bnc#801991,
    CVE-2013-0252)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-10/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801991"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected boost packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:boost-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:boost-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:boost-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:boost-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:boost-doc-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:boost-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:boost-license1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_chrono1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_chrono1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_date_time1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_date_time1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_date_time1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_date_time1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_filesystem1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_filesystem1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_filesystem1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_filesystem1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_graph1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_graph1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_graph1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_graph1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_iostreams1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_iostreams1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_iostreams1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_iostreams1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_locale1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_locale1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_math1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_math1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_math1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_math1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_mpi1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_mpi1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_mpi1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_mpi1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_program_options1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_program_options1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_program_options1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_program_options1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_python1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_python1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_python1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_python1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_random1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_random1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_random1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_random1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_regex1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_regex1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_regex1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_regex1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_serialization1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_serialization1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_serialization1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_serialization1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_signals1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_signals1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_signals1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_signals1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_system1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_system1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_system1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_system1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_test1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_test1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_test1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_test1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_thread1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_thread1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_thread1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_thread1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_timer1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_timer1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_wave1_49_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_wave1_49_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_wave1_49_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libboost_wave1_49_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"boost-debugsource-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"boost-devel-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"boost-doc-html-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"boost-doc-man-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"boost-doc-pdf-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"boost-license1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_chrono1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_chrono1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_date_time1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_date_time1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_filesystem1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_filesystem1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_graph1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_graph1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_iostreams1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_iostreams1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_locale1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_locale1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_math1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_math1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_mpi1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_mpi1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_program_options1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_program_options1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_python1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_python1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_random1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_random1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_regex1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_regex1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_serialization1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_serialization1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_signals1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_signals1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_system1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_system1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_test1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_test1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_thread1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_thread1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_timer1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_timer1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_wave1_49_0-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libboost_wave1_49_0-debuginfo-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"boost-devel-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_date_time1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_date_time1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_filesystem1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_filesystem1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_graph1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_graph1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_iostreams1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_iostreams1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_math1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_math1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_mpi1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_mpi1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_program_options1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_program_options1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_python1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_python1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_random1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_random1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_regex1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_regex1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_serialization1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_serialization1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_signals1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_signals1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_system1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_system1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_test1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_test1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_thread1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_thread1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_wave1_49_0-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libboost_wave1_49_0-debuginfo-32bit-1.49.0-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"boost-debugsource-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"boost-devel-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"boost-doc-html-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"boost-doc-man-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"boost-doc-pdf-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"boost-license1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_chrono1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_chrono1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_date_time1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_date_time1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_filesystem1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_filesystem1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_graph1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_graph1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_iostreams1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_iostreams1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_locale1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_locale1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_math1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_math1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_mpi1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_mpi1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_program_options1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_program_options1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_python1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_python1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_random1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_random1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_regex1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_regex1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_serialization1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_serialization1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_signals1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_signals1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_system1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_system1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_test1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_test1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_thread1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_thread1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_timer1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_timer1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_wave1_49_0-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libboost_wave1_49_0-debuginfo-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"boost-devel-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_date_time1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_date_time1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_filesystem1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_filesystem1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_graph1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_graph1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_iostreams1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_iostreams1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_math1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_math1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_mpi1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_mpi1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_program_options1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_program_options1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_python1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_python1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_random1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_random1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_regex1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_regex1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_serialization1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_serialization1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_signals1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_signals1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_system1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_system1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_test1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_test1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_thread1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_thread1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_wave1_49_0-32bit-1.49.0-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libboost_wave1_49_0-debuginfo-32bit-1.49.0-12.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "boost-debugsource / boost-devel / boost-devel-32bit / etc");
}
