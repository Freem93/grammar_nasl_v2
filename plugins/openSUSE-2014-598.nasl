#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-598.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(78635);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/23 10:48:28 $");

  script_cve_id("CVE-2014-7273", "CVE-2014-7274", "CVE-2014-7275");

  script_name(english:"openSUSE Security Update : getmail (openSUSE-SU-2014:1315-1)");
  script_summary(english:"Check for the openSUSE-2014-598 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - getmail 4.46.0 [bnc#900217] This release fixes several
    similar vulnerabilities that could allow a
    man-in-the-middle attacker to read encrypted traffic due
    to pack of certificate verification against the
    hostname.

  - fix --idle checking Python version incorrectly,
    resulting in incorrect warning about running with Python
    < 2.5

  - add missing support for SSL certificate checking in POP3
    which broke POP retrieval in v4.45.0 [CVE-2014-7275]

  - includes changes from 4.45.0 :

  - perform hostname-vs-certificate matching of SSL
    certificate if validating the certifcate [CVE-2014-7274]

  - fix missing plaintext versions of documentation

  - includes changes from 4.44.0 :

  - add extended SSL options for IMAP retrievers, allowing
    certificate verification and other features
    [CVE-2014-7273]

  - fix missing plaintext versions of documentation

  - fix 'Header instance has no attribute 'strip'' error
    which cropped up in some configurations"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-10/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900217"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected getmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:getmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"getmail-4.46.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"getmail-4.46.0-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "getmail");
}
