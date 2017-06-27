#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-44.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75015);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2012-5668", "CVE-2012-5669", "CVE-2012-5670");
  script_osvdb_id(88746, 88818, 88819);

  script_name(english:"openSUSE Security Update : freetype2 (openSUSE-SU-2013:0165-1)");
  script_summary(english:"Check for the openSUSE-2013-44 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - BNC#795826, CVE-2012-5668.patch [bdf] Fix Savannah bug
    #37905.

  - src/bdf/bdflib.c (_bdf_parse_start): Reset `props_size'
    to zero in case of allocation error; this value gets
    used in a loop in

  - BNC#795826, CVE-2012-5669.patch [bdf] Fix Savannah bug
    #37906.

  - src/bdf/bdflib.c (_bdf_parse_glyphs): Use correct array
    size for checking `glyph_enc'.

  - BNC#795826, CVE-2012-5670.patch [bdf] Fix Savannah bug
    #37907.

  - src/bdf/bdflib.c (_bdf_parse_glyphs) <ENCODING>:
    Normalize negative second parameter of `ENCODING' field
    also."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-01/msg00056.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ft2demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ft2demos-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ft2demos-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"freetype2-debugsource-2.4.9-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freetype2-devel-2.4.9-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ft2demos-2.4.9-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ft2demos-debuginfo-2.4.9-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"ft2demos-debugsource-2.4.9-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfreetype6-2.4.9-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfreetype6-debuginfo-2.4.9-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"freetype2-devel-32bit-2.4.9-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfreetype6-32bit-2.4.9-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfreetype6-debuginfo-32bit-2.4.9-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype2-debugsource / freetype2-devel / freetype2-devel-32bit / etc");
}
