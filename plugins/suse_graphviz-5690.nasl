#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update graphviz-5690.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34439);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:11:34 $");

  script_cve_id("CVE-2008-4555");

  script_name(english:"openSUSE 10 Security Update : graphviz (graphviz-5690)");
  script_summary(english:"Check for the graphviz-5690 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of graphviz fixes a buffer overflow that occurs while
parsing a DOT file. (CVE-2008-4555)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected graphviz packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-sharp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"graphviz-2.6-46") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"graphviz-devel-2.6-46") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"graphviz-tcl-2.6-46") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-devel-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-gd-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-guile-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-java-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-lua-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-ocaml-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-perl-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-php-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-python-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-ruby-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-sharp-2.12-50.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"graphviz-tcl-2.12-50.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphviz");
}
