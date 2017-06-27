#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-2826.
#

include("compat.inc");

if (description)
{
  script_id(82541);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 23:06:17 $");

  script_bugtraq_id(72806);
  script_xref(name:"FEDORA", value:"2015-2826");

  script_name(english:"Fedora 20 : drupal7-entity-1.6-1.fc20 (2015-2826)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 7.x-1.6

See [SA-CONTRIB-2015-053 - Entity API - Cross Site Scripting
(XSS)](https://www.drupal.org/node/2437905)

Changes since 7.x-1.5 :

  - by klausi: Sanitize field labels before passing them to
    the Token API.

    - Issue #2264079 by Amitaibu, fago: Fixed
      $wrapper->access() might be wrong for single entity
      reference field.

    - Issue #2039601 by DuaelFr, fago: Added Ease
      EntityMetadataWrapper usage with a getter.

    - Issue #2160355 by wodenx, gmercer, fgm, jgullstr:
      Fixed Trying to get property of non-object in
      entity_metadata_user_access().

    - Issue #1651824 by meatsack | joachim: Fixed
      'entity_test' table has incorrect declaration of
      foreign keys.

    - Issue #2309697 by kristiaanvandeneynde; joachim: Fixed
      variable mistake in
      entity_views_handler_relationship_by_bundle.

    - Issue #2003826 by greenmother, stella, jazzdrive3,
      fago: Fixed template_preprocess_entity does not check
      for existing 'path' index.

    - Issue #1104286: Support generating database schema for
      date properties.

    - Issue #2013473 by fietserwin: Title attribute of image
      field not listed as possible token.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1196750"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/154070.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae748ab8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.drupal.org/node/2437905"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal7-entity package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal7-entity");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"drupal7-entity-1.6-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal7-entity");
}
