#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-16020.
#

include("compat.inc");

if (description)
{
  script_id(79907);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 22:14:43 $");

  script_bugtraq_id(65003, 65223, 67068, 70238);
  script_xref(name:"FEDORA", value:"2014-16020");

  script_name(english:"Fedora 19 : mediawiki-1.23.7-1.fc19 (2014-16020)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://www.mediawiki.org/wiki/Release_notes/1.23#MediaWiki_1.23.7

  - (bug 66776, bug 71478) SECURITY: User PleaseStand
    reported a way to inject code into API clients that used
    format=php to process pages that underwent flash policy
    mangling. This was fixed along with improving how the
    mangling was done for format=json, and allowing sites to
    disable the mangling using $wgMangleFlashPolicy.

    - (bug 70901) SECURITY: User Jackmcbarn reported that
      the ability to update the content model for a page
      could allow an unprivileged attacker to edit another
      user's common.js under certain circumstances. The user
      right 'editcontentmodel' was added, and is needed to
      change a revision's content model.

    - (bug 71111) SECURITY: User PleaseStand reported that
      on wikis that allow raw HTML, it is not safe to
      preview wikitext coming from an untrusted source such
      as a cross-site request. Thus add an edit token to the
      form, and when raw HTML is allowed, ensure the token
      is provided before showing the preview. This check is
      not performed on wikis that both allow raw HTML and
      anonymous editing, since there are easier ways to
      exploit that scenario.

    - (bug 72222) SECURITY: Do not show log action when the
      entry is revdeleted with DELETED_ACTION. NOTICE: this
      may be reverted in a future release pending a public
      RFC about the desired functionality. This issue was
      reported by user Bawolff.

    - (bug 71621) Make allowing site-wide styles on
      restricted special pages a config option.

    - (bug 42723) Added updated version history from 1.19.2
      to 1.22.13

    - $wgMangleFlashPolicy was added to make MediaWiki's
      mangling of anything that might be a flash policy
      directive configurable.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mediawiki.org/wiki/Release_notes/1.23#MediaWiki_1.23.7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145910.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14816894"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mediawiki package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MediaWiki thumb.php page Parameter Remote Shell Command Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC19", reference:"mediawiki-1.23.7-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mediawiki");
}
