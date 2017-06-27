#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-20817.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71082);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 21:37:39 $");

  script_cve_id("CVE-2013-4519");
  script_bugtraq_id(63601);
  script_xref(name:"FEDORA", value:"2013-20817");

  script_name(english:"Fedora 18 : ReviewBoard-1.7.18-1.fc18 / python-djblets-0.7.23-1.fc18 (2013-20817)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix JavaScript errors

  - New upstream security release 1.7.17

    -
      http://www.reviewboard.org/docs/releasenotes/reviewboa
      rd/1.7.17/

    - Resolves: CVE-2013-4519

    - Security Fixes :

    - Fixed XSS vulnerabilities for the 'Branch' field and
      uploaded file captions.

    - Added a 'X-Frame-Options' header to prevent
      clickjacking.

    - New Features :

    - Remove the need for SSH keys for GitHub repositories.

    - Improved validation for GitHub repositories.

    - Added support for permissions on Local Sites.

    - Performance Improvements :

    - Reduced query counts on all pages.

    - Reduced query counts in the web API when returning
      empty lists.

    - Extensibility :

    - Extensions using the ``configure_extension`` view an
      now pass in a custom ``template_name`` pointing to a
      template for the configuration page, if it needs
      additional customization.

    - Enabling, disabling or reconfiguring extensions will
      now invalidate the caches for pages, ensuring that
      hooks will take affect.

    - Extension configuration now works properly on
      subdirectory installs.

    - Bug Fixes :

    - Fixed showing private review requests on a submitter
      page.

    - The description for submitted or discarded review
      requests is now shown on the diff viewer.

    - Discarding, reopening and then closing a review
      request no longer makes the review request private.

    - Fixed a naming conflict with older PyCrypto packages,
      such as the default package on CentOS 6.4.

    - Users with the 'can_change_status' permission no
      longer need the 'can_edit_reviewrequest' permission in
      order to close or reopen review requests.

    - Switching a repository from using a hosting service to
      Custom no longer reverts back to the hosting service.

    - Fixed editing a repository if its associated hosting
      service can't be loaded (such as if an extension
      providing that hosting service is disabled).

    - Many diff validation errors weren't being shown on the
      New Review Request page, generating 500 errors
      instead.

    - Fixed caching issues with the Blocks field on review
      requests.

    - Editing JSON text fields in the administration UI now
      works, validates, and won't result in warnings in the
      log.

    - Fixed breakages with looking up URLs internally with
      Local Sites.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.reviewboard.org/docs/releasenotes/reviewboard/1.7.17/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1027010"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-November/122663.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae806afb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-November/122664.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c7306ae"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ReviewBoard and / or python-djblets packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ReviewBoard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-djblets");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"ReviewBoard-1.7.18-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"python-djblets-0.7.23-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ReviewBoard / python-djblets");
}
