#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update namazu-5528.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75972);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/09 15:07:54 $");

  script_cve_id("CVE-2011-4345");
  script_osvdb_id(77267);

  script_name(english:"openSUSE Security Update : namazu (openSUSE-SU-2011:1327-1)");
  script_summary(english:"Check for the namazu-5528 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues :

  - 732323: CVE-2011-4345: namazu: XSS flaw by processing
    HTTP cookies (CVE-2011-4345)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-12/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732323"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected namazu packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:namazu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:namazu-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:namazu-cgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:namazu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:namazu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:namazu-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"namazu-2.0.20-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"namazu-cgi-2.0.20-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"namazu-cgi-debuginfo-2.0.20-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"namazu-debuginfo-2.0.20-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"namazu-debugsource-2.0.20-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"namazu-devel-2.0.20-5.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "namazu / namazu-cgi / namazu-devel / namazu-cgi-debuginfo / etc");
}
