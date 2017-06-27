#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-431.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76137);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/14 00:10:14 $");

  script_cve_id("CVE-2014-3985");

  script_name(english:"openSUSE Security Update : miniupnpc (openSUSE-SU-2014:0815-1)");
  script_summary(english:"Check for the openSUSE-2014-431 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"miniupnpc was updated to 1.9 to fix a potential buffer overrun in
miniwget.c (CVE-2014-3985).

Besides that the following issues were fixed :

  - added argument remoteHost to
    UPNP_GetSpecificPortMappingEntry()

  - increment API_VERSION to 10

  - --help and -h arguments in upnpc.c

  - define MAXHOSTNAMELEN if not already done

  - update upnpreplyparse to allow larger values (128 chars
    instead of 64) 

  - Update upnpreplyparse to take into account 'empty'
    elements

  - validate upnpreplyparse.c code with 'make check'

  - Fix Solaris build thanks to Maciej Ma&#x142;ecki

  - Fix testminiwget.sh for BSD

  - Fixed Makefile for *BSD

  - Update Makefile to use JNAerator version 0.11

  - Fix testminiwget.sh for use with dash

  - Use $(DESTDIR) in Makefile"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-06/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881990"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected miniupnpc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminiupnpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminiupnpc10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminiupnpc10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:miniupnpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:miniupnpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-miniupnpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-miniupnpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/19");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libminiupnpc-devel-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libminiupnpc10-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libminiupnpc10-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"miniupnpc-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"miniupnpc-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-miniupnpc-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-miniupnpc-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libminiupnpc-devel-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libminiupnpc10-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libminiupnpc10-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"miniupnpc-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"miniupnpc-debuginfo-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-miniupnpc-1.9-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-miniupnpc-debuginfo-1.9-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "miniupnpc");
}
