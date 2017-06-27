#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-506.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75042);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1988");
  script_bugtraq_id(60134);
  script_osvdb_id(93670);

  script_name(english:"openSUSE Security Update : libXres (openSUSE-SU-2013:1027-1)");
  script_summary(english:"Check for the openSUSE-2013-506 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libXres fixes several integer overflow issues.

  -
    U_0001-integer-overflow-in-XResQueryClients-CVE-2013-198
    8-1.patch,
    U_0002-integer-overflow-in-XResQueryClientResources-CVE-
    201.patch

  - integer overflow in XResQueryClients(),
    XResQueryClientResources() [CVE-2013-1988] (bnc#821663,
    bnc#815451)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00155.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821663"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libXres packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXRes1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXRes1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXRes1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXRes1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXres-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXres-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXres-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/07");
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

if ( rpm_check(release:"SUSE12.2", reference:"libXRes1-1.0.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXRes1-debuginfo-1.0.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXres-debugsource-1.0.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXres-devel-1.0.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXRes1-32bit-1.0.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXRes1-debuginfo-32bit-1.0.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXres-devel-32bit-1.0.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXRes1-1.0.6-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXRes1-debuginfo-1.0.6-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXres-debugsource-1.0.6-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXres-devel-1.0.6-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXRes1-32bit-1.0.6-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXRes1-debuginfo-32bit-1.0.6-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXres-devel-32bit-1.0.6-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXRes1 / libXRes1-32bit / libXRes1-debuginfo / etc");
}
