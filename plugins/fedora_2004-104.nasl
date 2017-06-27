#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-104.
#

include("compat.inc");

if (description)
{
  script_id(13687);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_xref(name:"FEDORA", value:"2004-104");

  script_name(english:"Fedora Core 1 : squid-2.5.STABLE3-1.fc1 (2004-104)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Mar 09 2004 Jay Fenlason <fenlason at redhat.com>
    7:2.5.STABLE3-1.fc1

  - Backport security fix for %00 hole. See CVE-2004-0189:
    The '%xx' URL decoding function in Squid 2.5STABLE4 and
    earlier allows remote attackers to bypass url_regex ACLs
    via a URL with a NULL ('%00') character, which causes
    Squid to use only a portion of the requested URL when
    comparing it against the access control lists.

  - Backport security fix that adds urllogin acl type that
    can be used to protect vulnerable Microsoft Internet
    Explorer clients.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-April/000105.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87ca6a6b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid and / or squid-debuginfo packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 1.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC1", reference:"squid-2.5.STABLE3-1.fc1")) flag++;
if (rpm_check(release:"FC1", reference:"squid-debuginfo-2.5.STABLE3-1.fc1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-debuginfo");
}
