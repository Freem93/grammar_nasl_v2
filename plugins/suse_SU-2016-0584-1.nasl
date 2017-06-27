#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0584-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(89021);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-7575", "CVE-2016-1523", "CVE-2016-1930", "CVE-2016-1935", "CVE-2016-1938");
  script_osvdb_id(132305, 133631, 133641, 133642, 133643, 133644, 133645, 133646, 133647, 133648, 133649, 133651, 133652, 133654, 133669, 134246);

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox, MozillaFirefox-branding-SLED, MozillaFirefox-branding-SLES-for-VMware, mozilla-nss (SUSE-SU-2016:0584-1) (SLOTH)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox, MozillaFirefox-branding-SLE,
mozilla-nss fixes the following issues :

Firefox 38.6.1 ESR (bsc#967087)

The following vulnerabilities were fixed :

  - CVE-2016-1523: Fixed denial of service in Graphite 2
    library (MFSA 2016-14/bmo#1246093)

Firefox 38.6.0 ESR + Mozilla NSS 3.20.2. (bsc#963520)

The following vulnerabilities were fixed :

  - CVE-2016-1930: Memory safety bugs fixed in Firefox ESR
    38.6 (bsc#963632)

  - CVE-2016-1935: Buffer overflow in WebGL after out of
    memory allocation (bsc#963635)

  - CVE-2016-1938: Calculations with mp_div and mp_exptmod
    in Network Security Services (NSS) canproduce wrong
    results (bsc#963731)

  - CVE-2015-7575: MD5 signatures accepted within TLS 1.2
    ServerKeyExchange in server signature (bsc#959888)

The following improvements were added :

  - bsc#954447: Mozilla NSS now supports a number of new DHE
    ciphersuites

  - Tracking protection is now enabled by default

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1523.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1930.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1935.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1938.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160584-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8b31aad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-mozilla-12419=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-mozilla-12419=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-17.5")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-17.5")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libfreebl3-32bit-3.20.2-17.5")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"mozilla-nss-32bit-3.20.2-17.5")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-38.6.1esr-33.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-branding-SLED-38-15.58")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-translations-38.6.1esr-33.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libfreebl3-3.20.2-17.5")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-3.20.2-17.5")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-devel-3.20.2-17.5")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-tools-3.20.2-17.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-SLED / MozillaFirefox-branding-SLES-for-VMware / mozilla-nss");
}
