#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-11682.
#

include("compat.inc");

if (description)
{
  script_id(67318);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_cve_id("CVE-2013-2209");
  script_bugtraq_id(60743);
  script_xref(name:"FEDORA", value:"2013-11682");

  script_name(english:"Fedora 19 : ReviewBoard-1.7.11-1.fc19 (2013-11682)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - New upstream release 1.7.11

    -
      http://www.reviewboard.org/docs/releasenotes/reviewboa
      rd/1.7.11/

    - Bug Fixes :

    - Fixed compatibility with Python 2.5

    - Fixed the drop-down arrow by Support and the account
      name on older versions of Internet Explorer

  - New upstream release 1.7.10

    -
      http://www.reviewboard.org/docs/releasenotes/reviewboa
      rd/1.7.10/

    - Security Updates :

    - Fixed an XSS vulnerability where users could trigger
      script errors under certain conditions in
      auto-complete widgets

  - Web API Changes :

    - Added n ?order-by=<fieldname> query parameter for
      comment resources, allowing ordering by fields such as
      line numbers (for diff comments)

  - Added a filename field to screenshot resources, which
    provides the base filename (without path) of the
    screenshot

  - Added a review_url field to screenshot resources, which
    provides the URL to the screenshot review page

  - Added a thumbnail_url field to screenshot comment
    resources, which provides the URL to the snippet of the
    screenshot being commented on

  - Added a link_text field to file attachment comment
    resources, which shows the text for any link pointing to
    the file. This may differ depending on the comment

  - Added a review_url field to file attachment comment
    resources, which provides the URL to the review page for
    the file

  - Added a thumbnail_html field to file attachment comment
    resources, which provides HTML for rendering the
    thumbnail of the portion of the file being rendered, if
    any

  - UI Changes :

    - Improved the look and feel of the issue summary table.
      It's cleaner and no longer looks odd with long
      comment text

  - Bug Fixes :

    - Fixed periodic but harmless JavaScript errors when
      removing elements with relative timestamps

  - Editing or reordering dashboard columns no longer breaks
    after the dashboard reloads

  - Relative timestamps in the dashboard no longer break
    after the dashboard reloads

  - The maximum size of the timezone has increased, allowing
    for longer timezone strings

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.reviewboard.org/docs/releasenotes/reviewboard/1.7.10/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.reviewboard.org/docs/releasenotes/reviewboard/1.7.11/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=977423"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/110842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15beef12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ReviewBoard package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ReviewBoard");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"ReviewBoard-1.7.11-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ReviewBoard");
}
