#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:0850-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83585);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-0788", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0797", "CVE-2013-0799", "CVE-2013-0800");
  script_bugtraq_id(58818, 58819, 58824, 58825, 58826, 58827, 58828, 58831, 58835, 58836, 58837);

  script_name(english:"SUSE SLES11 Security Update : Mozilla Firefox (SUSE-SU-2013:0850-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to the17.0.6ESR security version
upgrade as a LTSS roll up release.

MFSA 2013-30: Mozilla developers identified and fixed several memory
safety bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these bugs showed evidence of memory
corruption under certain circumstances, and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code.

Olli Pettay, Jesse Ruderman, Boris Zbarsky, Christian
Holler, Milan Sreckovic, and Joe Drew reported memory safety
problems and crashes that affect Firefox ESR 17, and Firefox
19. (CVE-2013-0788)

MFSA 2013-31 / CVE-2013-0800: Security researcher Abhishek
Arya (Inferno) of the Google Chrome Security Team used the
Address Sanitizer tool to discover an out-of-bounds write in
Cairo graphics library. When certain values are passed to it
during rendering, Cairo attempts to use negative boundaries
or sizes for boxes, leading to a potentially exploitable
crash in some instances.

MFSA 2013-32 / CVE-2013-0799: Security researcher Frederic
Hoguin discovered that the Mozilla Maintenance Service on
Windows was vulnerable to a buffer overflow. This system is
used to update software without invoking the User Account
Control (UAC) prompt. The Mozilla Maintenance Service is
configured to allow unprivileged users to start it with
arbitrary arguments. By manipulating the data passed in
these arguments, an attacker can execute arbitrary code with
the system privileges used by the service. This issue
requires local file system access to be exploitable.

MFSA 2013-34 / CVE-2013-0797: Security researcher Ash
reported an issue with the Mozilla Updater. The Mozilla
Updater can be made to load a malicious local DLL file in a
privileged context through either the Mozilla Maintenance
Service or independently on systems that do not use the
service. This occurs when the DLL file is placed in a
specific location on the local system before the Mozilla
Updater is run. Local file system access is necessary in
order for this issue to be exploitable.

MFSA 2013-35 / CVE-2013-0796: Security researcher miaubiz
used the Address Sanitizer tool to discover a crash in WebGL
rendering when memory is freed that has not previously been
allocated. This issue only affects Linux users who have
Intel Mesa graphics drivers. The resulting crash could be
potentially exploitable.

MFSA 2013-36 / CVE-2013-0795: Security researcher Cody Crews
reported a mechanism to use the cloneNode method to bypass
System Only Wrappers (SOW) and clone a protected node. This
allows violation of the browser's same origin policy and
could also lead to privilege escalation and the execution of
arbitrary code.

MFSA 2013-37 / CVE-2013-0794: Security researcher shutdown
reported a method for removing the origin indication on
tab-modal dialog boxes in combination with browser
navigation. This could allow an attacker's dialog to overlay
a page and show another site's content. This can be used for
phishing by allowing users to enter data into a modal prompt
dialog on an attacking, site while appearing to be from the
displayed site.

MFSA 2013-38 / CVE-2013-0793: Security researcher Mariusz
Mlynski reported a method to use browser navigations through
history to load an arbitrary website with that page's
baseURI property pointing to another site instead of the
seemingly loaded one. The user will continue to see the
incorrect site in the addressbar of the browser. This allows
for a cross-site scripting (XSS) attack or the theft of data
through a phishing attack.

MFSA 2013-39 / CVE-2013-0792: Mozilla community member
Tobias Schula reported that if gfx.color_management.enablev4
preference is enabled manually in about:config, some
grayscale PNG images will be rendered incorrectly and cause
memory corruption during PNG decoding when certain color
profiles are in use. A crafted PNG image could use this flaw
to leak data through rendered images drawing from random
memory. By default, this preference is not enabled.

MFSA 2013-40 / CVE-2013-0791: Mozilla community member
Ambroz Bizjak reported an out-of-bounds array read in the
CERT_DecodeCertPackage function of the Network Security
Services (NSS) libary when decoding a certificate. When this
occurs, it will lead to memory corruption and a
non-exploitable crash.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=237c6316d58c29602f03bb36ba67c991
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?521e501a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/819204"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20130850-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?230b14a5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP1 for VMware LTSS :

zypper in -t patch slessp1-firefox-20130516-7755

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-firefox-20130516-7755

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/31");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^1$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"libfreebl3-32bit-3.14.3-0.4.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.6-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.3-0.4.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"libfreebl3-32bit-3.14.3-0.4.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"mozilla-nspr-32bit-4.9.6-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"mozilla-nss-32bit-3.14.3-0.4.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"MozillaFirefox-17.0.6esr-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"MozillaFirefox-branding-SLED-7-0.6.9.20")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"MozillaFirefox-translations-17.0.6esr-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"libfreebl3-3.14.3-0.4.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"mozilla-nspr-4.9.6-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"mozilla-nss-3.14.3-0.4.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"mozilla-nss-tools-3.14.3-0.4.3.1")) flag++;


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
