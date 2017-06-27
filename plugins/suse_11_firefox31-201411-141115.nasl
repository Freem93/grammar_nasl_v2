# @DEPRECATED@
#
# This script has been deprecated as the associated patch is
# covered more completely by suse_SU-2014-1458-1.nasl,
# plugin id 83846.
#
# Disabled on 2015/05/26.
#

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
  script_id(79353);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/27 17:12:01 $");

  script_cve_id("CVE-2014-1574", "CVE-2014-1575", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1581", "CVE-2014-1583", "CVE-2014-1585", "CVE-2014-1586");

  script_name(english:"SuSE 11.3 Security Update : MozillaFirefox (SAT Patch Number 9972)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version update of Mozilla Firefox to 31.2.0ESR brings
improvements, stability fixes and also security fixes for the
following CVEs :

CVE-2014-1574 / CVE-2014-1575 / CVE-2014-1576 / CVE-2014-1577 /
CVE-2014-1578 / CVE-2014-1581 / CVE-2014-1583 / CVE-2014-1585 /
CVE-2014-1586

It also disables SSLv3 by default to mitigate the protocol downgrade
attack known as POODLE.

This update fixes some regressions introduced by the previously
released update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=900941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1574.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1576.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1581.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1586.html"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, 'The associated patch is now checked by suse_SU-2014-1458-1.nasl,\nplugin id 83846.');

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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-31.2.0esr-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-branding-SLED-31.0-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-31.2.0esr-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libfreebl3-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libsoftokn3-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nspr-4.10.7-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-tools-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-31.2.0esr-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-31.0-0.10.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-31.2.0esr-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-4.10.7-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.7-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-tools-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-31.2.0esr-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-branding-SLED-31.0-0.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-31.2.0esr-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libfreebl3-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libsoftokn3-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nspr-4.10.7-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-tools-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libfreebl3-32bit-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libsoftokn3-32bit-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.7-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nss-32bit-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.17.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.7-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.17.2-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
