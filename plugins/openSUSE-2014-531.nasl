#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-531.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77619);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/10/03 15:38:48 $");

  script_cve_id("CVE-2014-1553", "CVE-2014-1562", "CVE-2014-1563", "CVE-2014-1564", "CVE-2014-1565", "CVE-2014-1567");
  script_bugtraq_id(69519, 69520, 69521, 69523, 69524, 69525);

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-SU-2014:1098-1)");
  script_summary(english:"Check for the openSUSE-2014-531 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaThunderbird was updated to Thunderbird 31.1.0 (bnc#894370),
fixinfg security issues :

  - MFSA 2014-67/CVE-2014-1553/CVE-2014-1562 Miscellaneous
    memory safety hazards

  - MFSA 2014-68/CVE-2014-1563 (bmo#1018524) Use-after-free
    during DOM interactions with SVG

  - MFSA 2014-69/CVE-2014-1564 (bmo#1045977) Uninitialized
    memory use during GIF rendering

  - MFSA 2014-70/CVE-2014-1565 (bmo#1047831) Out-of-bounds
    read in Web Audio audio timeline

  - MFSA 2014-72/CVE-2014-1567 (bmo#1037641) Use-after-free
    setting text directionality

  - update to Thunderbird 31.0

  - based on Gecko 31

  - Autocompleting email addresses now matches against any
    part of the name or email

  - Composing a mail to a newsgroup will now autocomplete
    newsgroup names

  - Insecure NTLM (pre-NTLMv2) authentication disabled"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894370"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/11");
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

if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-31.1.0-61.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-buildsymbols-31.1.0-61.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debuginfo-31.1.0-61.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debugsource-31.1.0-61.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-31.1.0-61.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-common-31.1.0-61.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-other-31.1.0-61.59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-31.1.0-70.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-31.1.0-70.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-31.1.0-70.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-31.1.0-70.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-31.1.0-70.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-31.1.0-70.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-31.1.0-70.31.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird");
}
