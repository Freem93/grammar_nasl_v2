#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201412-09.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(79962);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id("CVE-2007-4370", "CVE-2009-4023", "CVE-2009-4111", "CVE-2010-0778", "CVE-2010-1780", "CVE-2010-1782", "CVE-2010-1783", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1788", "CVE-2010-1790", "CVE-2010-1791", "CVE-2010-1792", "CVE-2010-1793", "CVE-2010-1807", "CVE-2010-1812", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-2526", "CVE-2010-2901", "CVE-2010-3255", "CVE-2010-3257", "CVE-2010-3259", "CVE-2010-3362", "CVE-2010-3374", "CVE-2010-3389", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-3999", "CVE-2010-4042", "CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4204", "CVE-2010-4206", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4577", "CVE-2010-4578", "CVE-2011-0007", "CVE-2011-0465", "CVE-2011-0482", "CVE-2011-0721", "CVE-2011-0727", "CVE-2011-0904", "CVE-2011-0905", "CVE-2011-1072", "CVE-2011-1097", "CVE-2011-1144", "CVE-2011-1425", "CVE-2011-1572", "CVE-2011-1760", "CVE-2011-1951", "CVE-2011-2471", "CVE-2011-2472", "CVE-2011-2473", "CVE-2011-2524", "CVE-2011-3365", "CVE-2011-3366", "CVE-2011-3367");
  script_bugtraq_id(25297, 37081, 37395, 41148, 41976, 42033, 42034, 42035, 42036, 42037, 42038, 42041, 42042, 42043, 42044, 42045, 42046, 42049, 43047, 43079, 43081, 43083, 43672, 44204, 44206, 44241, 44349, 44359, 44563, 44954, 44960, 45170, 45390, 45715, 45718, 45719, 45720, 45721, 45722, 45788, 46426, 46473, 46605, 47063, 47064, 47135, 47189, 47650, 47652, 47681, 47800, 48241, 48926, 49925);
  script_xref(name:"GLSA", value:"201412-09");
  script_xref(name:"IAVA", value:"2017-A-0098");

  script_name(english:"GLSA-201412-09 : Multiple packages, Multiple vulnerabilities fixed in 2011");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-201412-09
(Multiple packages, Multiple vulnerabilities fixed in 2011)

    Vulnerabilities have been discovered in the packages listed below.
      Please review the CVE identifiers in the Reference section for details.
      FMOD Studio
      PEAR Mail
      LVM2
      GnuCash
      xine-lib
      Last.fm Scrobbler
      WebKitGTK+
      shadow tool suite
      PEAR
      unixODBC
      Resource Agents
      mrouted
      rsync
      XML Security Library
      xrdb
      Vino
      OProfile
      syslog-ng
      sFlow Toolkit
      GNOME Display Manager
      libsoup
      CA Certificates
      Gitolite
      QtCreator
      Racer
  
Impact :

    A context-dependent attacker may be able to gain escalated privileges,
      execute arbitrary code, cause Denial of Service, obtain sensitive
      information, or otherwise bypass security restrictions.
  
Workaround :

    There are no known workarounds at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201412-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All FMOD Studio users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/fmod-4.38.00'
    All PEAR Mail users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-php/PEAR-Mail-1.2.0'
    All LVM2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-fs/lvm2-2.02.72'
    All GnuCash users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-office/gnucash-2.4.4'
    All xine-lib users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/xine-lib-1.1.19'
    All Last.fm Scrobbler users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=media-sound/lastfmplayer-1.5.4.26862-r3'
    All WebKitGTK+ users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/webkit-gtk-1.2.7'
    All shadow tool suite users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-apps/shadow-4.1.4.3'
    All PEAR users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-php/PEAR-PEAR-1.9.2-r1'
    All unixODBC users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/unixODBC-2.3.0-r1'
    All Resource Agents users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=sys-cluster/resource-agents-1.0.4-r1'
    All mrouted users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/mrouted-3.9.5'
    All rsync users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/rsync-3.0.8'
    All XML Security Library users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/xmlsec-1.2.17'
    All xrdb users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-apps/xrdb-1.0.9'
    All Vino users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/vino-2.32.2'
    All OProfile users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-util/oprofile-0.9.6-r1'
    All syslog-ng users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-admin/syslog-ng-3.2.4'
    All sFlow Toolkit users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-analyzer/sflowtool-3.20'
    All GNOME Display Manager users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=gnome-base/gdm-3.8.4-r3'
    All libsoup users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/libsoup-2.34.3'
    All CA Certificates users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-misc/ca-certificates-20110502-r1'
    All Gitolite users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-vcs/gitolite-1.5.9.1'
    All QtCreator users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-util/qt-creator-2.1.0'
    Gentoo has discontinued support for Racer. We recommend that users
      unmerge Racer:
      # emerge --unmerge 'games-sports/racer-bin'
    NOTE: This is a legacy GLSA. Updates for all affected architectures have
      been available since 2012. It is likely that your system is already no
      longer affected by these issues."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Racer v0.5.3 Beta 5 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:PEAR-Mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:PEAR-PEAR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ca-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:fmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gitolite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gnucash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:lastfmplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:lvm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mrouted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oprofile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qt-creator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:racer-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sflowtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:shadow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:syslog-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xmlsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xrdb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"dev-db/unixODBC", unaffected:make_list("ge 2.3.0-r1"), vulnerable:make_list("lt 2.3.0-r1"))) flag++;
if (qpkg_check(package:"sys-apps/shadow", unaffected:make_list("ge 4.1.4.3"), vulnerable:make_list("lt 4.1.4.3"))) flag++;
if (qpkg_check(package:"sys-cluster/resource-agents", unaffected:make_list("ge 1.0.4-r1"), vulnerable:make_list("lt 1.0.4-r1"))) flag++;
if (qpkg_check(package:"net-misc/rsync", unaffected:make_list("ge 3.0.8"), vulnerable:make_list("lt 3.0.8"))) flag++;
if (qpkg_check(package:"app-office/gnucash", unaffected:make_list("ge 2.4.4"), vulnerable:make_list("lt 2.4.4"))) flag++;
if (qpkg_check(package:"dev-util/qt-creator", unaffected:make_list("ge 2.1.0"), vulnerable:make_list("lt 2.1.0"))) flag++;
if (qpkg_check(package:"app-misc/ca-certificates", unaffected:make_list("ge 20110502-r1"), vulnerable:make_list("lt 20110502-r1"))) flag++;
if (qpkg_check(package:"net-libs/libsoup", unaffected:make_list("ge 2.34.3"), vulnerable:make_list("lt 2.34.3"))) flag++;
if (qpkg_check(package:"app-admin/syslog-ng", unaffected:make_list("ge 3.2.4"), vulnerable:make_list("lt 3.2.4"))) flag++;
if (qpkg_check(package:"gnome-base/gdm", unaffected:make_list("ge 3.8.4-r3"), vulnerable:make_list("lt 3.8.4-r3"))) flag++;
if (qpkg_check(package:"dev-php/PEAR-PEAR", unaffected:make_list("ge 1.9.2-r1"), vulnerable:make_list("lt 1.9.2-r1"))) flag++;
if (qpkg_check(package:"dev-php/PEAR-Mail", unaffected:make_list("ge 1.2.0"), vulnerable:make_list("lt 1.2.0"))) flag++;
if (qpkg_check(package:"dev-util/oprofile", unaffected:make_list("ge 0.9.6-r1"), vulnerable:make_list("lt 0.9.6-r1"))) flag++;
if (qpkg_check(package:"net-libs/webkit-gtk", unaffected:make_list("ge 1.2.7"), vulnerable:make_list("lt 1.2.7"))) flag++;
if (qpkg_check(package:"media-sound/lastfmplayer", unaffected:make_list("ge 1.5.4.26862-r3"), vulnerable:make_list("lt 1.5.4.26862-r3"))) flag++;
if (qpkg_check(package:"games-sports/racer-bin", unaffected:make_list(), vulnerable:make_list("ge 0.5.0-r1"))) flag++;
if (qpkg_check(package:"sys-fs/lvm2", unaffected:make_list("ge 2.02.72"), vulnerable:make_list("lt 2.02.72"))) flag++;
if (qpkg_check(package:"dev-vcs/gitolite", unaffected:make_list("ge 1.5.9.1"), vulnerable:make_list("lt 1.5.9.1"))) flag++;
if (qpkg_check(package:"net-analyzer/sflowtool", unaffected:make_list("ge 3.20"), vulnerable:make_list("lt 3.20"))) flag++;
if (qpkg_check(package:"x11-apps/xrdb", unaffected:make_list("ge 1.0.9"), vulnerable:make_list("lt 1.0.9"))) flag++;
if (qpkg_check(package:"media-libs/fmod", unaffected:make_list("ge 4.38.00"), vulnerable:make_list("lt 4.38.00"))) flag++;
if (qpkg_check(package:"dev-libs/xmlsec", unaffected:make_list("ge 1.2.17"), vulnerable:make_list("lt 1.2.17"))) flag++;
if (qpkg_check(package:"net-misc/mrouted", unaffected:make_list("ge 3.9.5"), vulnerable:make_list("lt 3.9.5"))) flag++;
if (qpkg_check(package:"media-libs/xine-lib", unaffected:make_list("ge 1.1.19"), vulnerable:make_list("lt 1.1.19"))) flag++;
if (qpkg_check(package:"net-misc/vino", unaffected:make_list("ge 2.32.2"), vulnerable:make_list("lt 2.32.2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dev-db/unixODBC / sys-apps/shadow / sys-cluster/resource-agents / etc");
}
