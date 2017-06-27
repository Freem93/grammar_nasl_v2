#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2081-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87063);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4497", "CVE-2015-4498", "CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4506", "CVE-2015-4509", "CVE-2015-4511", "CVE-2015-4513", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_osvdb_id(126004, 126005, 126006, 126007, 126008, 126009, 126010, 126011, 126012, 126013, 126015, 126016, 126021, 126022, 126023, 126024, 126025, 126026, 126027, 126028, 126767, 126768, 127875, 127876, 127877, 127878, 127879, 127880, 127881, 127882, 127883, 127884, 127890, 127892, 127899, 127915, 127916, 127917, 127918, 127919, 127920, 127921, 127922, 127923, 127924, 129763, 129764, 129765, 129766, 129767, 129768, 129769, 129770, 129771, 129772, 129773, 129782, 129783, 129784, 129785, 129789, 129790, 129791, 129797, 129798, 129799, 129800, 129801);

  script_name(english:"SUSE SLES10 Security Update : Mozilla Firefox (SUSE-SU-2015:2081-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox ESR was updated to version 38.4.0ESR to fix multiple
security issues.

MFSA 2015-116/CVE-2015-4513 Miscellaneous memory safety hazards
(rv:42.0 / rv:38.4)

MFSA 2015-122/CVE-2015-7188 Trailing whitespace in IP address
hostnames can bypass same-origin policy

MFSA 2015-123/CVE-2015-7189 Buffer overflow during image interactions
in canvas

MFSA 2015-127/CVE-2015-7193 CORS preflight is bypassed when
non-standard Content-Type headers are received

MFSA 2015-128/CVE-2015-7194 Memory corruption in libjar through zip
files

MFSA 2015-130/CVE-2015-7196 JavaScript garbage collection crash with
Java applet

MFSA 2015-131/CVE-2015-7198/CVE-2015-7199/CVE-2015-7200
Vulnerabilities found through code inspection

MFSA 2015-132/CVE-2015-7197 Mixed content WebSocket policy bypass
through workers

MFSA 2015-133/CVE-2015-7181/CVE-2015-7182/CVE-2015-7183 NSS and NSPR
memory corruption issues

It also includes fixes from 38.3.0ESR :

MFSA 2015-96/CVE-2015-4500/CVE-2015-4501 Miscellaneous memory safety
hazards (rv:41.0 / rv:38.3)

MFSA 2015-101/CVE-2015-4506 Buffer overflow in libvpx while parsing
vp9 format video

MFSA 2015-105/CVE-2015-4511 Buffer overflow while decoding WebM video

MFSA 2015-106/CVE-2015-4509 Use-after-free while manipulating HTML
media content

MFSA 2015-110/CVE-2015-4519 Dragging and dropping images exposes final
URL after redirects

MFSA 2015-111/CVE-2015-4520 Errors in the handling of CORS preflight
request headers

MFSA 2015-112/CVE-2015-4517/CVE-2015-4521/CVE-2015-4522
CVE-2015-7174/CVE-2015-7175/CVE-2015-7176/CVE-2015-7177 CVE-2015-7180
Vulnerabilities found through code inspection

It also includes fixes from the Firefox 38.2.1ESR release :

MFSA 2015-94/CVE-2015-4497 (bsc#943557) Use-after-free when resizing
canvas element during restyling

MFSA 2015-95/CVE-2015-4498 (bsc#943558) Add-on notification bypass
through data URLs

It also includes fixes from the Firefox 38.2.0ESR release :

MFSA 2015-79/CVE-2015-4473/CVE-2015-4474 Miscellaneous memory safety
hazards (rv:40.0 / rv:38.2)

MFSA 2015-80/CVE-2015-4475 Out-of-bounds read with malformed MP3 file

MFSA 2015-82/CVE-2015-4478 Redefinition of non-configurable JavaScript
object properties

MFSA 2015-83/CVE-2015-4479 Overflow issues in libstagefright

MFSA 2015-87/CVE-2015-4484 Crash when using shared memory in
JavaScript

MFSA 2015-88/CVE-2015-4491 Heap overflow in gdk-pixbuf when scaling
bitmap images

MFSA 2015-89/CVE-2015-4485/CVE-2015-4486 Buffer overflows on Libvpx
when decoding WebM video

MFSA 2015-90/CVE-2015-4487/CVE-2015-4488/CVE-2015-4489 Vulnerabilities
found through code inspection

MFSA 2015-92/CVE-2015-4492 Use-after-free in XMLHttpRequest with
shared workers

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952810"
  );
  # https://download.suse.com/patch/finder/?keywords=bb006e2ed6738badb2b7f4f52e5c1b2a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7ef3af1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4474.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4475.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4489.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4498.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4500.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4501.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4520.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4521.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4522.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7174.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7175.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7176.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7189.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7193.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7197.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7198.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7199.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7200.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152081-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7087ca82"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox packages"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.19.2.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"mozilla-nss-32bit-3.19.2.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nspr-4.10.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nspr-devel-4.10.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nss-3.19.2.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nss-devel-3.19.2.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nss-tools-3.19.2.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-38.4.0esr-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-branding-SLED-38-0.5.3")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-translations-38.4.0esr-0.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox");
}
