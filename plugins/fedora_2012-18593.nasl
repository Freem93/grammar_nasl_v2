#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-18593.
#

include("compat.inc");

if (description)
{
  script_id(63131);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/20 22:34:53 $");

  script_xref(name:"FEDORA", value:"2012-18593");

  script_name(english:"Fedora 18 : claws-mail-3.9.0-1.fc18 / claws-mail-plugins-3.9.0-2.fc18 (2012-18593)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Added IMAP server side search

    - Added the file .claws-mail/extraheaderrc which holds
      editable extra headers to be added to compose window
      combobox

    - Added 'Select html part of multipart messages' to the
      Folder Properties

    - GnuPG: Consider marginal signature validity as
      untrusted

    - The mimeview shortcuts are now user configurable

    - Spell checker: Always show 'change dictionary' menu

    - Filtering dialogue: TreeView type-ahead is now case
      insensitive

    - Separated 'Mark all read' from 'Mark as read' and
      'Ignore thread'

    - Made 'Mark all read' confirmation button more clear

    - Made the clickable area of the expander arrows in the
      folder list larger

    - Made SSL client certificate error messages more
      meaningful

    - The type of units required in the Extended Search
      information dialogue are now indicated

    - Several speed-ups and optimizations

    - Updated manual

    - Updated translations: Brazilian Portuguese, Finnish,
      French, German, Hungarian, Spanish, Swedish,
      traditional Chinese, Ukrainian

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=877375"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-December/093764.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bf49318"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-December/093765.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67603ec3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected claws-mail and / or claws-mail-plugins packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC18", reference:"claws-mail-3.9.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"claws-mail-plugins-3.9.0-2.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "claws-mail / claws-mail-plugins");
}
