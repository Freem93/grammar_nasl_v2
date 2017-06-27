#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-1774.
#

include("compat.inc");

if (description)
{
  script_id(64544);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_cve_id("CVE-2013-0235");
  script_bugtraq_id(57554);
  script_xref(name:"FEDORA", value:"2013-1774");

  script_name(english:"Fedora 18 : wordpress-3.5.1-1.fc18 (2013-1774)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"WordPress 3.5.1 is now available. Version 3.5.1 is the first
maintenance release of 3.5, fixing 37 bugs. It is also a security
release for all previous WordPress versions. Which include :

  - Editor: Prevent certain HTML elements from being
    unexpectedly removed or modified in rare cases.

    - Media: Fix a collection of minor workflow and
      compatibility issues in the new media manager.

    - Networks: Suggest proper rewrite rules when creating a
      new network.

    - Prevent scheduled posts from being stripped of certain
      HTML, such as video embeds, when they are published.

    - Work around some misconfigurations that may have
      caused some JavaScript in the WordPress admin area to
      fail.

    - Suppress some warnings that could occur when a plugin
      misused the database or user APIs.

WordPress 3.5.1 also addresses the following security issues :

  - A server-side request forgery vulnerability and remote
    port scanning using pingbacks. This vulnerability, which
    could potentially be used to expose information and
    compromise a site, affects all previous WordPress
    versions. This was fixed by the WordPress security team.
    We'd like to thank security researchers Gennady
    Kovshenin and Ryan Dewhurst for reviewing our work.

    - Two instances of cross-site scripting via shortcodes
      and post content. These issues were discovered by Jon
      Cave of the WordPress security team.

    - A cross-site scripting vulnerability in the external
      library Plupload. Thanks to the Moxiecode team for
      working with us on this, and for releasing Plupload
      1.5.5 to address this issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=904120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=904121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=904122"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/098476.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8f719cf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/11");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"wordpress-3.5.1-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wordpress");
}
