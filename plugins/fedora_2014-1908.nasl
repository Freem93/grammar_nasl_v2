#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-1908.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(72448);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:23:31 $");

  script_cve_id("CVE-2013-4509");
  script_bugtraq_id(63516);
  script_xref(name:"FEDORA", value:"2014-1908");

  script_name(english:"Fedora 20 : ibus-chewing-1.4.10.1-1.fc20 (2014-1908)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Resolves Bug 1054937 - Broken %defattr in ibus-chewing

    - Fix Build for RHEL7

    - Resolves Bug 1013977 - ibus-chewing needs to have ibus
      write-cache --system in %post and %postun

    - Resolves Bug 1027031 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [rhel-7.0]

    - Resolves Bug 1028911 - [zh_TW]'Chinese<->English'
      switch does not work when clicking on the Chewing menu
      list.

    - Resolves Bug 1045868 - ibus-chewing *again* not built
      with $RPM_OPT_FLAGS

    - Option 'Sync between caps lock and IM': + Default of
      is changed to 'disable', because the previous default
      'keyboard' cause bug 1028911 for GNOME Shell. + Now
      Sync from 'input method' can control Caps LED in GNOME
      shell.

  - Translation added: de_DE, es_ES, it_IT, pt_BR, uk_UA

    - Set environment IBUS_CHEWING_LOGFILE for ibus-chewing
      log.

    - Resolves Bug 842856 - ibus-chewing 1.4.3-1 not built
      with $RPM_OPT_FLAGS

    - Resolves Bug 1027030 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [fedora-all] Thanks
      czchen for the GitHub pull request 39.

  - Added translations: fr_FR, ja_JP, ko_KR

    - Adopt cmake-fedora-1.2.0

    - Resolves Bug 842856 - ibus-chewing 1.4.3-1 not built
      with $RPM_OPT_FLAGS

    - Resolves Bug 1027030 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [fedora-all] Thanks
      czchen for the GitHub pull request 39.

  - Added translations: fr_FR, ja_JP, ko_KR

    - Adopt cmake-fedora-1.2.0

    - Resolves Bug 1013977 - ibus-chewing needs to have ibus
      write-cache --system in %post and %postun

    - Resolves Bug 1027031 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [rhel-7.0]

    - Resolves Bug 1028911 - [zh_TW]'Chinese<->English'
      switch does not work when clicking on the Chewing menu
      list.

    - Resolves Bug 1045868 - ibus-chewing *again* not built
      with $RPM_OPT_FLAGS

    - Option 'Sync between caps lock and IM': + Default of
      is changed to 'disable', because the previous default
      'keyboard' cause bug 1028911 for GNOME Shell. + Now
      Sync from 'input method' can control Caps LED in GNOME
      shell.

  - Translation added: de_DE, es_ES, it_IT, pt_BR, uk_UA

    - Set environment IBUS_CHEWING_LOGFILE for ibus-chewing
      log.

    - Resolves Bug 842856 - ibus-chewing 1.4.3-1 not built
      with $RPM_OPT_FLAGS

    - Resolves Bug 1027030 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [fedora-all] Thanks
      czchen for the GitHub pull request 39.

  - Added translations: fr_FR, ja_JP, ko_KR

    - Adopt cmake-fedora-1.2.0

    - Resolves Bug 842856 - ibus-chewing 1.4.3-1 not built
      with $RPM_OPT_FLAGS

    - Resolves Bug 1027030 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [fedora-all] Thanks
      czchen for the GitHub pull request 39.

  - Added translations: fr_FR, ja_JP, ko_KR

    - Adopt cmake-fedora-1.2.0

    - Fix Build for RHEL7

    - Resolves Bug 1013977 - ibus-chewing needs to have ibus
      write-cache --system in %post and %postun

    - Resolves Bug 1027031 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [rhel-7.0]

    - Resolves Bug 1028911 - [zh_TW]'Chinese<->English'
      switch does not work when clicking on the Chewing menu
      list.

    - Resolves Bug 1045868 - ibus-chewing *again* not built
      with $RPM_OPT_FLAGS

    - Option 'Sync between caps lock and IM': + Default of
      is changed to 'disable', because the previous default
      'keyboard' cause bug 1028911 for GNOME Shell. + Now
      Sync from 'input method' can control Caps LED in GNOME
      shell.

  - Translation added: de_DE, es_ES, it_IT, pt_BR, uk_UA

    - Set environment IBUS_CHEWING_LOGFILE for ibus-chewing
      log.

    - Resolves Bug 842856 - ibus-chewing 1.4.3-1 not built
      with $RPM_OPT_FLAGS

    - Resolves Bug 1027030 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [fedora-all] Thanks
      czchen for the GitHub pull request 39.

  - Added translations: fr_FR, ja_JP, ko_KR

    - Adopt cmake-fedora-1.2.0

    - Resolves Bug 842856 - ibus-chewing 1.4.3-1 not built
      with $RPM_OPT_FLAGS

    - Resolves Bug 1027030 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [fedora-all] Thanks
      czchen for the GitHub pull request 39.

  - Added translations: fr_FR, ja_JP, ko_KR

    - Adopt cmake-fedora-1.2.0

    - Resolves Bug 1013977 - ibus-chewing needs to have ibus
      write-cache --system in %post and %postun

    - Resolves Bug 1027031 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [rhel-7.0]

    - Resolves Bug 1028911 - [zh_TW]'Chinese<->English'
      switch does not work when clicking on the Chewing menu
      list.

    - Resolves Bug 1045868 - ibus-chewing *again* not built
      with $RPM_OPT_FLAGS

    - Option 'Sync between caps lock and IM': + Default of
      is changed to 'disable', because the previous default
      'keyboard' cause bug 1028911 for GNOME Shell. + Now
      Sync from 'input method' can control Caps LED in GNOME
      shell.

  - Translation added: de_DE, es_ES, it_IT, pt_BR, uk_UA

    - Set environment IBUS_CHEWING_LOGFILE for ibus-chewing
      log.

    - Resolves Bug 842856 - ibus-chewing 1.4.3-1 not built
      with $RPM_OPT_FLAGS

    - Resolves Bug 1027030 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [fedora-all] Thanks
      czchen for the GitHub pull request 39.

  - Added translations: fr_FR, ja_JP, ko_KR

    - Adopt cmake-fedora-1.2.0

    - Resolves Bug 842856 - ibus-chewing 1.4.3-1 not built
      with $RPM_OPT_FLAGS

    - Resolves Bug 1027030 - CVE-2013-4509 ibus-chewing:
      ibus: visible password entry flaw [fedora-all] Thanks
      czchen for the GitHub pull request 39.

  - Added translations: fr_FR, ja_JP, ko_KR

    - Adopt cmake-fedora-1.2.0

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1013977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1027030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1028911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1045868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=842856"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-February/128124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af62aad0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ibus-chewing package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ibus-chewing");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/12");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"ibus-chewing-1.4.10.1-1.fc20")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ibus-chewing");
}
