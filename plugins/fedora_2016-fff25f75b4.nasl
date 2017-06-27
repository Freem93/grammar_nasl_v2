#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-fff25f75b4.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(92624);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/07/29 13:51:07 $");

  script_xref(name:"FEDORA", value:"2016-fff25f75b4");

  script_name(english:"Fedora 24 : drupal7-views (2016-fff25f75b4)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes [Views - Less Critical - Access Bypass -
SA-CONTRIB-2016-036](https://www.drupal.org/node/2749333)

Changes since 7.x-3.13 :

  - Adding field handlers for statistics fields

  - \#2200309 by helmo: Changed invalid placeholder from
    'handler' to 'extender'.

  - \#2708535 by stefan.r: Allow users to sort on a specific
    language, showing it before any others

  - \#1359298 by robertwb: Support Plugins for Views
    Aggregate in D7 (D8 Backport)

  - \#1358412 by davidgrayston, marcelovani, jamiecuthill,
    mikeytown2, ParisLiakos, Josh Waihi: Content: Has
    taxonomy term ID (with depth) query performance

  - \#1615438 by rsmylski, MediaFormat, awolfey,
    ParisLiakos: Search terms: nodes dont appear when using
    multiple arguments

  - Revert 'Issue #1615438 by rsmylski, MediaFormat,
    awolfey, ParisLiakos: Search terms: nodes dont appear
    when using multiple arguments'

  - \#1567354 by joelpittet, robcolburn: Stop lowercasing
    undefined values.

  - \#1535912 by dawehner, joelpittet: Remove
    no-longer-necessary $condition variable.

  - \#981870 by infojunkie, joelpittet, andypost:
    views::get_url() to skip default arguments

  - \#959048 by rooby, dawehner, joelpittet, pyry_p: Added a
    revision count.

  - \#2563431 by joelpittet, lauriii: ajax_render should not
    be used; ajax_deliver should be used instead

  - \#564106 by rv0 et al.: More link to point to custom URL

  - Revert 'Issue #564106 by dawehner et al.: More link to
    point to custom URL'

  - \#1608920 by dawehner, rudiedirkx, axel.rutz,
    solotandem, Anybody, JvE, helior: Add drop-button field
    display

  - \#1482824 by DeFr, Alan Evans, robertom: Block display
    view ajax pager does not advance with multiple pagers on
    a page when the first pager > 0

  - \#1232920 by dawehner, Anybody, chiddicks: Hide earlier
    in the process.

  - \#1190900 by ls, philipz, Neograph734, Oniryck: Random
    sort from multiple value field in views

  - \#1090432 by fubhy, derhasi, rudiedirkx, IT-Cru: Allow
    additional field-to-field conditions with the default
    views_join handler

  - \#652610 by johnv, dawehner, colan, Les Lim: Stop
    caching when not set.

  - \#564106 by dawehner et al.: More link to point to
    custom URL

  - \#1948578 by jweowu: Duplicate code. Issue #1515156
    patch applied twice

  - Merge branch '7.x-3.x' of git.drupal.org:project/views
    into 7.x-3.x

  - Revert 'Issue #2290127 by DanChadwick: pre_render not
    consistently passed result by reference'

  - \#1685144 by marcelovani, dawehner, q0rban: Refactor
    init_localization() to init and return the translate
    property for all plugins.

  - \#1262630 by damiankloip: Raw value tokens not replaced
    if used in css class

  - \#1262630 by Jelle_S, dgtlmoon: Raw value tokens not
    replaced if used in css class

  - \#2290127 by DanChadwick: pre_render not consistently
    passed result by reference

  - \#551808 by dawehner, axel.rutz: Provide
    hook_views_save, hook_view_delete

  - \#339384 by lotyrin, neuquen, marcingy, colan: Default
    option not set in exposed filters when terms are
    selected

  - \#2610292 by dawehner: Fix 7.x-3.x-dev test failures.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-fff25f75b4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal7-views package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal7-views");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"drupal7-views-3.14-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal7-views");
}
