#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-486.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75027);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2013-2064");
  script_bugtraq_id(60148);
  script_osvdb_id(93664);

  script_name(english:"openSUSE Security Update : libxcb (openSUSE-SU-2013:1007-1)");
  script_summary(english:"Check for the openSUSE-2013-486 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libxcb fixes a integer overflow issue :

  -
    U_0001-integer-overflow-in-read_packet-CVE-2013-2064.pat
    ch 

  - fixes integer overflow in read_packet() [CVE-2013-2064]
    (bnc#821584, bnc#815451)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821584"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxcb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xevie0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xevie0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xevie0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xevie0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xprint0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xprint0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xprint0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xprint0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.2", reference:"libxcb-composite0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-composite0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-damage0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-damage0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-debugsource-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-devel-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-dpms0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-dpms0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-dri2-0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-dri2-0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-glx0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-glx0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-randr0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-randr0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-record0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-record0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-render0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-render0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-res0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-res0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-screensaver0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-screensaver0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-shape0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-shape0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-shm0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-shm0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-sync0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-sync0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xevie0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xevie0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xf86dri0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xf86dri0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xfixes0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xfixes0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xinerama0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xinerama0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xprint0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xprint0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xtest0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xtest0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xv0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xv0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xvmc0-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb-xvmc0-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb1-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxcb1-debuginfo-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-composite0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-composite0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-damage0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-damage0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-devel-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-dpms0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-dpms0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-dri2-0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-dri2-0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-glx0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-glx0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-randr0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-randr0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-record0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-record0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-render0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-render0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-res0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-res0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-screensaver0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-screensaver0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-shape0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-shape0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-shm0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-shm0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-sync0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-sync0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xevie0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xevie0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xf86dri0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xf86dri0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xfixes0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xfixes0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xinerama0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xinerama0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xprint0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xprint0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xtest0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xtest0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xv0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xv0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xvmc0-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb-xvmc0-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb1-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libxcb1-debuginfo-32bit-1.8.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-composite0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-composite0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-damage0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-damage0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-debugsource-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-devel-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-dpms0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-dpms0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-dri2-0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-dri2-0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-glx0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-glx0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-randr0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-randr0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-record0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-record0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-render0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-render0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-res0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-res0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-screensaver0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-screensaver0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-shape0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-shape0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-shm0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-shm0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-sync0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-sync0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xevie0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xevie0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xf86dri0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xf86dri0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xfixes0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xfixes0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xinerama0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xinerama0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xprint0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xprint0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xtest0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xtest0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xv0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xv0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xvmc0-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb-xvmc0-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb1-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxcb1-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-composite0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-composite0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-damage0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-damage0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-devel-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-dpms0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-dpms0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-dri2-0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-dri2-0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-glx0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-glx0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-randr0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-randr0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-record0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-record0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-render0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-render0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-res0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-res0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-screensaver0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-screensaver0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-shape0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-shape0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-shm0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-shm0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-sync0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-sync0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xevie0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xevie0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xf86dri0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xf86dri0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xfixes0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xfixes0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xinerama0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xinerama0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xprint0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xprint0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xtest0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xtest0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xv0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xv0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xvmc0-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb-xvmc0-debuginfo-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb1-32bit-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libxcb1-debuginfo-32bit-1.9-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxcb-composite0 / libxcb-composite0-32bit / etc");
}
