#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-60753c3dcd.
#

include("compat.inc");

if (description)
{
  script_id(95780);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/14 14:43:07 $");

  script_cve_id("CVE-2016-9920");
  script_xref(name:"FEDORA", value:"2016-60753c3dcd");

  script_name(english:"Fedora 24 : roundcubemail (2016-60753c3dcd)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 1.2.3**

  - Searching in both contacts and groups when LDAP
    addressbook with group_filters option is used

  - Fix vulnerability in handling of mail()'s 5th argument

  - Fix To: header encoding in mail sent with mail() method
    (#5475)

  - Fix flickering of header topline in min-mode (#5426)

  - Fix bug where folders list would scroll to top when
    clicking on subscription checkbox (#5447)

  - Fix decoding of GB2312/GBK text when iconv is not
    installed (#5448)

  - Fix regression where creation of default folders wasn't
    functioning without prefix (#5460)

  - Enigma: Fix bug where last records on keys list were
    hidden (#5461)

  - Enigma: Fix key search with keyword containing non-ascii
    characters (#5459)

  - Fix bug where deleting folders with subfolders could
    fail in some cases (#5466)

  - Fix bug where IMAP password could be exposed via error
    message (#5472)

  - Fix bug where it wasn't possible to store more that 2MB
    objects in memcache/apc, Added
    memcache_max_allowed_packet and apc_max_allowed_packet
    settings (#5452)

  - Fix 'Illegal string offset' warning in rcube::log_bug()
    on PHP 7.1 (#5508)

  - Fix storing 'empty' values in
    rcube_cache/rcube_cache_shared (#5519)

  - Fix missing content check when image resize fails on
    attachment thumbnail generation (#5485)

  - Fix displaying attached images with wrong Content-Type
    specified (#5527)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-60753c3dcd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");
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
if (rpm_check(release:"FC24", reference:"roundcubemail-1.2.3-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
