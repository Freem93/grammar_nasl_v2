#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0665-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83622);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2014-1492", "CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_bugtraq_id(66356, 67123, 67129, 67130, 67131, 67134, 67135, 67137);

  script_name(english:"SUSE SLES10 Security Update : Mozilla Firefox (SUSE-SU-2014:0665-2)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Mozilla Firefox update provides several security and non-security
fixes.

Mozilla Firefox has been updated to the 24.5.0esr version, which fixes
the following issues :

  - MFSA 2014-34/CVE-2014-1518 Miscellaneous memory safety
    hazards

  - MFSA 2014-37/CVE-2014-1523 Out of bounds read while
    decoding JPG images

  - MFSA 2014-38/CVE-2014-1524 Buffer overflow when using
    non-XBL object as XBL

  - MFSA 2014-42/CVE-2014-1529 Privilege escalation through
    Web Notification API

  - MFSA 2014-43/CVE-2014-1530 Cross-site scripting (XSS)
    using history navigations

  - MFSA 2014-44/CVE-2014-1531 Use-after-free in imgLoader
    while resizing images

  - MFSA 2014-46/CVE-2014-1532 Use-after-free in
    nsHostResolver

Mozilla NSS has been updated to version 3.16

  - required for Firefox 29

  - CVE-2014-1492_ In a wildcard certificate, the wildcard
    character should not be embedded within the U-label of
    an internationalized domain name. See the last bullet
    point in RFC 6125, Section 7.2.

  - Update of root certificates.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=286e8d629532f85ab01bea1a26438953
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?755a37c4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1523.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1524.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1529.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1532.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/865539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/869827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/875378"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140665-2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e61318c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-atk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-cairo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-fontconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-freetype2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-gtk2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-pcre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-pixman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-xulrunner191");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-xulrunner191-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-xulrunner191-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-xulrunner192-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-atk-32bit-1.28.0-0.7.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-cairo-32bit-1.8.0-0.10.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-fontconfig-32bit-2.6.0-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-freetype2-32bit-2.3.7-0.35.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-glib2-32bit-2.22.5-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-gtk2-32bit-2.18.9-0.9.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-libgcc_s1-32bit-4.7.2_20130108-0.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-libstdc++6-32bit-4.7.2_20130108-0.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-pango-32bit-1.26.2-0.9.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-pcre-32bit-7.8-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox-pixman-32bit-0.16.0-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.16-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.19-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.19-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.19-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.28-0.13.4")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.28-0.13.4")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.28-0.13.4")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-atk-32bit-1.28.0-0.7.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-cairo-32bit-1.8.0-0.10.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-fontconfig-32bit-2.6.0-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-freetype2-32bit-2.3.7-0.35.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-glib2-32bit-2.22.5-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-gtk2-32bit-2.18.9-0.9.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-libgcc_s1-32bit-4.7.2_20130108-0.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-libstdc++6-32bit-4.7.2_20130108-0.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-pango-32bit-1.26.2-0.9.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-pcre-32bit-7.8-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox-pixman-32bit-0.16.0-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-nss-32bit-3.16-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-xulrunner191-32bit-1.9.1.19-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.19-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.19-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-xulrunner192-32bit-1.9.2.28-0.13.4")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.28-0.13.4")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.28-0.13.4")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-atk-1.28.0-0.7.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-cairo-1.8.0-0.10.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-fontconfig-2.6.0-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-freetype2-2.3.7-0.35.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-glib2-2.22.5-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-gtk2-2.18.9-0.9.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-gtk2-lang-2.18.9-0.9.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-libgcc_s1-4.7.2_20130108-0.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-libstdc++6-4.7.2_20130108-0.22.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-pango-1.26.2-0.9.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-pcre-7.8-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox-pixman-0.16.0-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nspr-4.10.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nspr-devel-4.10.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nss-3.16-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nss-devel-3.16-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nss-tools-3.16-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-xulrunner191-1.9.1.19-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.19-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-xulrunner191-translations-1.9.1.19-0.13.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-xulrunner192-1.9.2.28-0.13.4")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-xulrunner192-gnome-1.9.2.28-0.13.4")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-xulrunner192-translations-1.9.2.28-0.13.4")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"MozillaFirefox-24.5.0esr-0.7.2")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"MozillaFirefox-branding-SLED-24-0.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"MozillaFirefox-translations-24.5.0esr-0.7.2")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox");
}
