#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(74007);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/28 19:00:58 $");

  script_cve_id("CVE-2013-6629", "CVE-2013-6954", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2402", "CVE-2014-2403", "CVE-2014-2412", "CVE-2014-2413", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427");

  script_name(english:"SuSE 11.3 Security Update : OpenJDK (SAT Patch Number 9209)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This java-1_7_0-openjdk update to version 2.4.7 fixes the following
security and non-security issues :

  - Security fixes

  - S8023046: Enhance splashscreen support

  - S8025005: Enhance CORBA initializations

  - S8025010, CVE-2014-2412: Enhance AWT contexts

  - S8025030, CVE-2014-2414: Enhance stream handling

  - S8025152, CVE-2014-0458: Enhance activation set up

  - S8026067: Enhance signed jar verification

  - S8026163, CVE-2014-2427: Enhance media provisioning

  - S8026188, CVE-2014-2423: Enhance envelope factory

  - S8026200: Enhance RowSet Factory

  - S8026716, CVE-2014-2402: (aio) Enhance asynchronous
    channel handling

  - S8026736, CVE-2014-2398: Enhance Javadoc pages

  - S8026797, CVE-2014-0451: Enhance data transfers

  - S8026801, CVE-2014-0452: Enhance endpoint addressing

  - S8027766, CVE-2014-0453: Enhance RSA processing

  - S8027775: Enhance ICU code.

  - S8027841, CVE-2014-0429: Enhance pixel manipulations

  - S8028385: Enhance RowSet Factory

  - S8029282, CVE-2014-2403: Enhance CharInfo set up

  - S8029286: Enhance subject delegation

  - S8029699: Update Poller demo

  - S8029730: Improve audio device additions

  - S8029735: Enhance service mgmt natives

  - S8029740, CVE-2014-0446: Enhance handling of loggers

  - S8029745, CVE-2014-0454: Enhance algorithm checking

  - S8029750: Enhance LCMS color processing (in-tree LCMS)

  - S8029760, CVE-2013-6629: Enhance AWT image libraries
    (in-tree libjpeg)

  - S8029844, CVE-2014-0455: Enhance argument validation

  - S8029854, CVE-2014-2421: Enhance JPEG decodings

  - S8029858, CVE-2014-0456: Enhance array copies

  - S8030731, CVE-2014-0460: Improve name service robustness

  - S8031330: Refactor ObjectFactory

  - S8031335, CVE-2014-0459: Better color profiling (in-tree
    LCMS)

  - S8031352, CVE-2013-6954: Enhance PNG handling (in-tree
    libpng)

  - S8031394, CVE-2014-0457: (sl) Fix exception handling in
    ServiceLoader

  - S8031395: Enhance LDAP processing

  - S8032686, CVE-2014-2413: Issues with method invoke

  - S8033618, CVE-2014-1876: Correct logging output

  - S8034926, CVE-2014-2397: Attribute classes properly

  - S8036794, CVE-2014-0461: Manage JavaScript instances

  - Backports

  - S8004145: New improved hgforest.sh, ctrl-c now properly
    terminates mercurial processes.

  - S8007625: race with nested repos in
    /common/bin/hgforest.sh

  - S8011178: improve common/bin/hgforest.sh python
    detection (MacOS)

  - S8011342: hgforest.sh : 'python --version' not supported
    on older python

  - S8011350: hgforest.sh uses non-POSIX sh features that
    may fail with some shells

  - S8024200: handle hg wrapper with space after #!

  - S8025796: hgforest.sh could trigger unbuffered output
    from hg without complicated machinations

  - S8028388: 9 jaxws tests failed in nightly build with
    java.lang.ClassCastException

  - S8031477: [macosx] Loading AWT native library fails

  - S8032370: No 'Truncated file' warning from
    IIOReadWarningListener on JPEGImageReader

  - S8035834: InetAddress.getLocalHost() can hang after
    JDK-8030731 was fixed

  - Bug fixes

  - PR1393: JPEG support in build is broken on
    non-system-libjpeg builds

  - PR1726: configure fails looking for ecj.jar before even
    trying to find javac

  - Red Hat local: Fix for repo with path statting with / .

  - Remove unused hgforest script"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=873873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6629.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6954.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0452.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0453.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0454.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0455.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0460.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2397.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2398.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2403.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2413.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2414.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2427.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9209.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"java-1_7_0-openjdk-1.7.0.6-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"java-1_7_0-openjdk-demo-1.7.0.6-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"java-1_7_0-openjdk-devel-1.7.0.6-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.6-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.6-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.6-0.27.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
