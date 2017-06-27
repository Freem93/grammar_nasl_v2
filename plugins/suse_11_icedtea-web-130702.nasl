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
  script_id(68953);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/22 11:17:46 $");

  script_cve_id("CVE-2012-3422", "CVE-2012-3423", "CVE-2013-1926", "CVE-2013-1927");

  script_name(english:"SuSE 11.3 Security Update : icedtea-web (SAT Patch Number 7981)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to IcedTea-Web 1.4 provides the following fixes and
enhancements :

  - Security updates

  - RH916774: Class-loader incorrectly shared for applets
    with same relative-path. (CVE-2013-1926)

  - RH884705: fixed gifar vulnerabilit. (CVE-2013-1927)

  - RH840592: Potential read from an uninitialized memory
    location. (CVE-2012-3422)

  - RH841345: Incorrect handling of not 0-terminated
    strings. (CVE-2012-3423)

  - RH884705: fixed gifar vulnerability. (CVE-2013-1927)

  - RH916774: Class-loader incorrectly shared for applets
    with same relative-path. (CVE-2013-1926)

  - NetX

  - PR1027: DownloadService is not supported by IcedTea-Web

  - PR725: JNLP applications will prompt for creating
    desktop shortcuts every time they are run

  - PR1292: Javaws does not resolve versioned jar names with
    periods correctly

  - PR580: http://www.horaoficial.cl/ loads improperly.

  - Plugin

  - PR1106: Buffer overflow in plugin table-

  - PR1166: Embedded JNLP File is not supported in applet
    tag

  - PR1217: Add command line arguments for plugins

  - PR1189: Icedtea-plugin requires code attribute when
    using jnlp_href

  - PR1198: JSObject is not passed to JavaScript correctly

  - PR1260: IcedTea-Web should not rely on GTK

  - PR1157: Applets can hang browser after fatal exception

  - PR580: http://www.horaoficial.cl/ loads improperly

  - PR1260: IcedTea-Web should not rely on GTK

  - PR1157: Applets can hang browser after fatal exception.

  - Common

  - PR1049: Extension jnlp's signed jar with the content of
    only META-INF/* is considered

  - PR955: regression: SweetHome3D fails to run

  - PR1145: IcedTea-Web can cause ClassCircularityError

  - PR1161: X509VariableTrustManager does not work correctly
    with OpenJDK7

  - PR822: Applets fail to load if jars have different
    signers

  - PR1186:
    System.getProperty('deployment.user.security.trusted.cac
    erts') is null

  - PR909: The Java applet at
    http://de.gosupermodel.com/games/wardrobegame.jsp fails

  - PR1299: WebStart doesn't read socket proxy settings from
    firefox correctly.

  - Added cs, de, pl localization

  - Splash screen for javaws and plugin

  - Better error reporting for plugin via
    Error-splash-screen

  - All IcedTea-Web dialogues are centered to middle of
    active screen

  - Download indicator made compact for more then one jar

  - User can select its own JVM via itw-settings and
    deploy.properties

  - Added extended applets security settings and dialogue

  - Added new option in itw-settings which allows users to
    set JVM arguments when plugin is initialized

  - Fixed a build failure with older xulrunner

  - Changed strict openjdk6 dependencies to anything
    java-openjdk >= 1.6.0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1926.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1927.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7981.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"icedtea-web-1.4-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"icedtea-web-1.4-0.10.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
