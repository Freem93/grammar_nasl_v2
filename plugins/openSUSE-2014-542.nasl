#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-542.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77718);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/24 13:49:14 $");

  script_cve_id("CVE-2014-0472", "CVE-2014-0473", "CVE-2014-0474", "CVE-2014-0480", "CVE-2014-0481", "CVE-2014-0482", "CVE-2014-0483", "CVE-2014-1418", "CVE-2014-3730");

  script_name(english:"openSUSE Security Update : python-django (openSUSE-SU-2014:1132-1)");
  script_summary(english:"Check for the openSUSE-2014-542 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Python Django was updated to fix security issues and bugs.

Update to version 1.4.15 on openSUSE 12.3 :

  + Prevented reverse() from generating URLs pointing to
    other hosts to prevent phishing attacks (bnc#893087,
    CVE-2014-0480)

  + Removed O(n) algorithm when uploading duplicate file
    names to fix file upload denial of service (bnc#893088,
    CVE-2014-0481)

  + Modified RemoteUserMiddleware to logout on REMOTE_USE
    change to prevent session hijacking (bnc#893089,
    CVE-2014-0482)

  + Prevented data leakage in contrib.admin via query string
    manipulation (bnc#893090, CVE-2014-0483)

  + Fixed: Caches may incorrectly be allowed to store and
    serve private data (bnc#877993, CVE-2014-1418)

  + Fixed: Malformed redirect URLs from user input not
    correctly validated (bnc#878641, CVE-2014-3730)

  + Fixed queries that may return unexpected results on
    MySQL due to typecasting (bnc#874956, CVE-2014-0474)

  + Prevented leaking the CSRF token through caching
    (bnc#874955, CVE-2014-0473)

  + Fixed a remote code execution vulnerability in URL
    reversing (bnc#874950, CVE-2014-0472)

Update to version 1.5.10 on openSUSE 13.1 :

  + Prevented reverse() from generating URLs pointing to
    other hosts to prevent phishing attacks (bnc#893087,
    CVE-2014-0480)

  + Removed O(n) algorithm when uploading duplicate file
    names to fix file upload denial of service (bnc#893088,
    CVE-2014-0481)

  + Modified RemoteUserMiddleware to logout on REMOTE_USE
    change to prevent session hijacking (bnc#893089,
    CVE-2014-0482)

  + Prevented data leakage in contrib.admin via query string
    manipulation (bnc#893090, CVE-2014-0483)

  - Update to version 1.5.8 :

  + Fixed: Caches may incorrectly be allowed to store and
    serve private data (bnc#877993, CVE-2014-1418)

  + Fixed: Malformed redirect URLs from user input not
    correctly validated (bnc#878641, CVE-2014-3730)

  + Fixed queries that may return unexpected results on
    MySQL due to typecasting (bnc#874956, CVE-2014-0474)

  + Prevented leaking the CSRF token through caching
    (bnc#874955, CVE-2014-0473)

  + Fixed a remote code execution vulnerability in URL
    reversing (bnc#874950, CVE-2014-0472)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=874950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=874955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=874956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=877993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893090"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.3", reference:"python-django-1.4.15-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-django-1.5.10-0.2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-django");
}
