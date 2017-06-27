#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update texlive-2392.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(46344);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 20:06:04 $");

  script_cve_id("CVE-2010-0739", "CVE-2010-0827", "CVE-2010-0829", "CVE-2010-1440");

  script_name(english:"openSUSE Security Update : texlive (openSUSE-SU-2010:0251-1)");
  script_summary(english:"Check for the texlive-2392 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted dvi files could cause buffer overflows in dvips and
dvipng (CVE-2010-0827, CVE-2010-0829, CVE-2010-0739, CVE-2010-1440)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-05/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=587794"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected texlive packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-arab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-cjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-dvilj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-musictex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-omega");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-ppower4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-tex4ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-xmltex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"texlive-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-arab-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-bin-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-cjk-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-context-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-devel-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-dvilj-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-jadetex-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-latex-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-metapost-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-musictex-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-nfs-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-omega-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-ppower4-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-tex4ht-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-tools-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-xetex-2008-13.18.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"texlive-xmltex-2008-13.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "texlive / texlive-arab / texlive-bin / texlive-cjk / etc");
}
