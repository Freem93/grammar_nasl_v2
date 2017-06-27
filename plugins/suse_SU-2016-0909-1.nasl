#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0909-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90263);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-1978", "CVE-2016-1979", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_osvdb_id(135550, 135551, 135552, 135553, 135554, 135555, 135556, 135557, 135558, 135559, 135560, 135561, 135562, 135563, 135564, 135565, 135566, 135567, 135568, 135569, 135570, 135571, 135572, 135573, 135574, 135575, 135576, 135579, 135580, 135582, 135583, 135584, 135591, 135592, 135595, 135602, 135603, 135604, 135605, 135606, 135607, 135608, 135609, 135610, 135611, 135612, 135613, 135614, 135615, 135616, 135617, 135618, 135718);

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox, mozilla-nspr, mozilla-nss (SUSE-SU-2016:0909-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox, mozilla-nspr, mozilla-nss fixes the
following issues :

Mozilla Firefox was updated to 38.7.0 ESR (bsc#969894), fixing
following security issues :

  - MFSA 2016-16/CVE-2016-1952/CVE-2016-1953 Miscellaneous
    memory safety hazards (rv:45.0 / rv:38.7)

  - MFSA 2016-17/CVE-2016-1954 Local file overwriting and
    potential privilege escalation through CSP reports

  - MFSA 2016-20/CVE-2016-1957 Memory leak in libstagefright
    when deleting an array during MP4 processing

  - MFSA 2016-21/CVE-2016-1958 Displayed page address can be
    overridden

  - MFSA 2016-23/CVE-2016-1960 Use-after-free in HTML5
    string parser

  - MFSA 2016-24/CVE-2016-1961 Use-after-free in SetBody

  - MFSA 2016-25/CVE-2016-1962 Use-after-free when using
    multiple WebRTC data channels

  - MFSA 2016-27/CVE-2016-1964 Use-after-free during XML
    transformations

  - MFSA 2016-28/CVE-2016-1965 Addressbar spoofing though
    history navigation and Location protocol property

  - MFSA 2016-31/CVE-2016-1966 Memory corruption with
    malicious NPAPI plugin

  - MFSA 2016-34/CVE-2016-1974 Out-of-bounds read in HTML
    parser following a failed allocation

  - MFSA 2016-35/CVE-2016-1950 Buffer overflow during ASN.1
    decoding in NSS

  - MFSA 2016-37/CVE-2016-1977/CVE-2016-2790/CVE-2016-2791/
    CVE-2016-2792/CVE-2016-2793/CVE-2016-2794/CVE-2016-2795/
    CVE-2016-2796/CVE-2016-2797/CVE-2016-2798/CVE-2016-2799/
    CVE-2016-2800/CVE-2016-2801/CVE-2016-2802 Font
    vulnerabilities in the Graphite 2 library

Mozilla NSPR was updated to version 4.12 (bsc#969894), fixing
following bugs :

  - added a PR_GetEnvSecure function, which attempts to
    detect if the program is being executed with elevated
    privileges, and returns NULL if detected. It is
    recommended to use this function in general purpose
    library code.

  - fixed a memory allocation bug related to the PR_*printf
    functions

  - exported API PR_DuplicateEnvironment, which had already
    been added in NSPR 4.10.9

  - added support for FreeBSD aarch64

  - several minor correctness and compatibility fixes

Mozilla NSS was updated to fix security issues (bsc#969894) :

  - MFSA 2016-15/CVE-2016-1978 Use-after-free in NSS during
    SSL connections in low memory

  - MFSA 2016-35/CVE-2016-1950 Buffer overflow during ASN.1
    decoding in NSS

  - MFSA 2016-36/CVE-2016-1979 Use-after-free during
    processing of DER encoded keys in NSS

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1950.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1952.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1953.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1954.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1957.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1958.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1960.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1961.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1962.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1964.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1965.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1966.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1974.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1977.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1978.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1979.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2790.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2791.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2792.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2793.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2794.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2795.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2796.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2801.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2802.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160909-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?739bce44"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-firefox-20160310-12483=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-firefox-20160310-12483=1

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
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
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-20.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-20.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libfreebl3-32bit-3.20.2-20.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"mozilla-nspr-32bit-4.12-19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"mozilla-nss-32bit-3.20.2-20.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-38.7.0esr-36.3")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-translations-38.7.0esr-36.3")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libfreebl3-3.20.2-20.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nspr-4.12-19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nspr-devel-4.12-19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-3.20.2-20.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-devel-3.20.2-20.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-tools-3.20.2-20.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / mozilla-nspr / mozilla-nss");
}
