#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-677.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86594);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/10/26 14:28:14 $");

  script_cve_id("CVE-2015-5143", "CVE-2015-5144");

  script_name(english:"openSUSE Security Update : python-Django (openSUSE-2015-677)");
  script_summary(english:"Check for the openSUSE-2015-677 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"python-django was updated to fix two security issues.

These security issues were fixed :

  - CVE-2015-5144: Django before 1.4.21, 1.5.x through
    1.6.x, 1.7.x before 1.7.9, and 1.8.x before 1.8.3 used
    an incorrect regular expression, which allowed remote
    attackers to inject arbitrary headers and conduct HTTP
    response splitting attacks via a newline character in an
    (1) email message to the EmailValidator, a (2) URL to
    the URLValidator, or unspecified vectors to the (3)
    validate_ipv4_address or (4) validate_slug validator
    (bsc#937523).

  - CVE-2015-5143: The session backends in Django before
    1.4.21, 1.5.x through 1.6.x, 1.7.x before 1.7.9, and
    1.8.x before 1.8.3 allowed remote attackers to cause a
    denial of service (session store consumption) via
    multiple requests with unique session keys (bsc#937522)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937523"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-Django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-Django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"python-Django-1.6.11-3.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-Django");
}
