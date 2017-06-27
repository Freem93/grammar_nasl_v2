#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201412-08.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(79961);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2006-3005", "CVE-2007-2741", "CVE-2008-0553", "CVE-2008-1382", "CVE-2008-5907", "CVE-2008-6218", "CVE-2008-6661", "CVE-2009-0040", "CVE-2009-0360", "CVE-2009-0361", "CVE-2009-0946", "CVE-2009-2042", "CVE-2009-2624", "CVE-2009-3736", "CVE-2009-4029", "CVE-2009-4411", "CVE-2009-4896", "CVE-2010-0001", "CVE-2010-0436", "CVE-2010-0732", "CVE-2010-0829", "CVE-2010-1000", "CVE-2010-1205", "CVE-2010-1511", "CVE-2010-2056", "CVE-2010-2060", "CVE-2010-2192", "CVE-2010-2251", "CVE-2010-2529", "CVE-2010-2809", "CVE-2010-2945");
  script_bugtraq_id(24001, 27655, 28770, 31920, 32751, 33740, 33741, 33827, 33990, 34550, 35233, 37128, 37378, 37455, 37886, 37888, 38211, 39467, 39969, 40141, 40426, 40516, 40939, 41174, 41841, 41911, 42297, 43728);
  script_xref(name:"GLSA", value:"201412-08");

  script_name(english:"GLSA-201412-08 : Multiple packages, Multiple vulnerabilities fixed in 2010");
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
"The remote host is affected by the vulnerability described in GLSA-201412-08
(Multiple packages, Multiple vulnerabilities fixed in 2010)

    Vulnerabilities have been discovered in the packages listed below.
      Please review the CVE identifiers in the Reference section for details.
      Insight
      Perl Tk Module
      Source-Navigator
      Tk
      Partimage
      Mlmmj
      acl
      Xinit
      gzip
      ncompress
      liblzw
      splashutils
      GNU M4
      KDE Display Manager
      GTK+
      KGet
      dvipng
      Beanstalk
      Policy Mount
      pam_krb5
      GNU gv
      LFTP
      Uzbl
      Slim
      Bitdefender Console
      iputils
      DVBStreamer
  
Impact :

    A context-dependent attacker may be able to gain escalated privileges,
      execute arbitrary code, cause Denial of Service, obtain sensitive
      information, or otherwise bypass security restrictions.
  
Workaround :

    There are no known workarounds at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201412-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Insight users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-util/insight-6.7.1-r1'
    All Perl Tk Module users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-perl/perl-tk-804.028-r2'
    All Source-Navigator users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-util/sourcenav-5.1.4'
    All Tk users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/tk-8.4.18-r1'
    All Partimage users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-block/partimage-0.6.8'
    All Mlmmj users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-mail/mlmmj-1.2.17.1'
    All acl users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-apps/acl-2.2.49'
    All Xinit users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-apps/xinit-1.2.0-r4'
    All gzip users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-arch/gzip-1.4'
    All ncompress users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-arch/ncompress-4.2.4.3'
    All liblzw users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/liblzw-0.2'
    All splashutils users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=media-gfx/splashutils-1.5.4.3-r3'
    All GNU M4 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-devel/m4-1.4.14-r1'
    All KDE Display Manager users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=kde-base/kdm-4.3.5-r1'
    All GTK+ users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/gtk+-2.18.7'
    All KGet 4.3 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=kde-base/kget-4.3.5-r1'
    All dvipng users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-text/dvipng-1.13'
    All Beanstalk users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-misc/beanstalkd-1.4.6'
    All Policy Mount users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-apps/pmount-0.9.23'
    All pam_krb5 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-auth/pam_krb5-4.3'
    All GNU gv users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-text/gv-3.7.1'
    All LFTP users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-ftp/lftp-4.0.6'
    All Uzbl users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/uzbl-2010.08.05'
    All Slim users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-misc/slim-1.3.2'
    All iputils users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/iputils-20100418'
    All DVBStreamer users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-tv/dvbstreamer-1.1-r1'
    Gentoo has discontinued support for Bitdefender Console. We recommend
      that users unmerge Bitdefender Console:
      # emerge --unmerge 'app-antivirus/bitdefender-console'
    NOTE: This is a legacy GLSA. Updates for all affected architectures have
      been available since 2011. It is likely that your system is already no
      longer affected by these issues."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 119, 189, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:acl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:beanstalkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bitdefender-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dvbstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dvipng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gtk+");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:insight");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:iputils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:lftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:liblzw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:m4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mlmmj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ncompress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pam_krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:partimage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:perl-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:slim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sourcenav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:splashutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:uzbl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xinit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-arch/gzip", unaffected:make_list("ge 1.4"), vulnerable:make_list("lt 1.4"))) flag++;
if (qpkg_check(package:"kde-base/kget", unaffected:make_list("ge 4.3.5-r1"), vulnerable:make_list("lt 4.3.5-r1"))) flag++;
if (qpkg_check(package:"app-text/dvipng", unaffected:make_list("ge 1.13"), vulnerable:make_list("lt 1.13"))) flag++;
if (qpkg_check(package:"x11-apps/xinit", unaffected:make_list("ge 1.2.0-r4"), vulnerable:make_list("lt 1.2.0-r4"))) flag++;
if (qpkg_check(package:"sys-apps/pmount", unaffected:make_list("ge 0.9.23"), vulnerable:make_list("lt 0.9.23"))) flag++;
if (qpkg_check(package:"sys-block/partimage", unaffected:make_list("ge 0.6.8"), vulnerable:make_list("lt 0.6.8"))) flag++;
if (qpkg_check(package:"app-arch/ncompress", unaffected:make_list("ge 4.2.4.3"), vulnerable:make_list("lt 4.2.4.3"))) flag++;
if (qpkg_check(package:"sys-apps/acl", unaffected:make_list("ge 2.2.49"), vulnerable:make_list("lt 2.2.49"))) flag++;
if (qpkg_check(package:"sys-devel/m4", unaffected:make_list("ge 1.4.14-r1"), vulnerable:make_list("lt 1.4.14-r1"))) flag++;
if (qpkg_check(package:"dev-util/insight", unaffected:make_list("ge 6.7.1-r1"), vulnerable:make_list("lt 6.7.1-r1"))) flag++;
if (qpkg_check(package:"media-tv/dvbstreamer", unaffected:make_list("ge 1.1-r1"), vulnerable:make_list("lt 1.1-r1"))) flag++;
if (qpkg_check(package:"net-misc/iputils", unaffected:make_list("ge 20100418"), vulnerable:make_list("lt 20100418"))) flag++;
if (qpkg_check(package:"sys-auth/pam_krb5", unaffected:make_list("ge 4.3"), vulnerable:make_list("lt 4.3"))) flag++;
if (qpkg_check(package:"dev-lang/tk", unaffected:make_list("ge 8.4.18-r1"), vulnerable:make_list("lt 8.4.18-r1"))) flag++;
if (qpkg_check(package:"dev-perl/perl-tk", unaffected:make_list("ge 804.028-r2"), vulnerable:make_list("lt 804.028-r2"))) flag++;
if (qpkg_check(package:"dev-libs/liblzw", unaffected:make_list("ge 0.2"), vulnerable:make_list("lt 0.2"))) flag++;
if (qpkg_check(package:"kde-base/kdm", unaffected:make_list("ge 4.3.5-r1"), vulnerable:make_list("lt 4.3.5-r1"))) flag++;
if (qpkg_check(package:"net-ftp/lftp", unaffected:make_list("ge 4.0.6"), vulnerable:make_list("lt 4.0.6"))) flag++;
if (qpkg_check(package:"net-mail/mlmmj", unaffected:make_list("ge 1.2.17.1"), vulnerable:make_list("lt 1.2.17.1"))) flag++;
if (qpkg_check(package:"media-gfx/splashutils", unaffected:make_list("ge 1.5.4.3-r3"), vulnerable:make_list("lt 1.5.4.3-r3"))) flag++;
if (qpkg_check(package:"www-client/uzbl", unaffected:make_list("ge 2010.08.05"), vulnerable:make_list("lt 2010.08.05"))) flag++;
if (qpkg_check(package:"app-antivirus/bitdefender-console", unaffected:make_list(), vulnerable:make_list("le 7.1"))) flag++;
if (qpkg_check(package:"app-text/gv", unaffected:make_list("ge 3.7.1"), vulnerable:make_list("lt 3.7.1"))) flag++;
if (qpkg_check(package:"app-misc/beanstalkd", unaffected:make_list("ge 1.4.6"), vulnerable:make_list("lt 1.4.6"))) flag++;
if (qpkg_check(package:"x11-libs/gtk+", unaffected:make_list("ge 2.18.7"), vulnerable:make_list("lt 2.18.7"))) flag++;
if (qpkg_check(package:"dev-util/sourcenav", unaffected:make_list("ge 5.1.4"), vulnerable:make_list("lt 5.1.4"))) flag++;
if (qpkg_check(package:"x11-misc/slim", unaffected:make_list("ge 1.3.2"), vulnerable:make_list("lt 1.3.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "app-arch/gzip / kde-base/kget / app-text/dvipng / x11-apps/xinit / etc");
}
