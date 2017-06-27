#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-2251.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27116);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:31:03 $");

  script_cve_id("CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748");

  script_name(english:"openSUSE 10 Security Update : MozillaFirefox (MozillaFirefox-2251)");
  script_summary(english:"Check for the MozillaFirefox-2251 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings MozillaFirefox to the security update release
1.5.0.8, including the following security fixes.

Full details can be found on:
http://www.mozilla.org/projects/security/known-vulnerabilities.html

MFSA2006-65: Is split into 3 sub-entries, for ongoing stability
improvements in the Mozilla browsers: CVE-2006-5464: Layout engine
flaws were fixed. CVE-2006-5747: A xml.prototype.hasOwnProperty flaw
was fixed. CVE-2006-5748: Fixes were applied to the JavaScript engine.

MFSA2006-66/CVE-2006-5462: MFSA 2006-60 reported that RSA digital
signatures with a low exponent (typically 3) could be forged. Firefox
and Thunderbird 1.5.0.7, which incorporated NSS version 3.10.2, were
incompletely patched and remained vulnerable to a variant of this
attack.

MFSA2006-67/CVE-2006-5463: shutdown demonstrated that it was possible
to modify a Script object while it was executing, potentially leading
to the execution of arbitrary JavaScript bytecode."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"MozillaFirefox-1.5.0.8-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"MozillaFirefox-translations-1.5.0.8-0.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
