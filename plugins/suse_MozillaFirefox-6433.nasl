#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41468);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 6433)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to the 3.0.13 release, fixing some security
issues and bugs :

  - Security researcher Juan Pablo Lopez Yacubian reported
    that an attacker could call window.open() on an invalid
    URL which looks similar to a legitimate URL and then use
    document.write() to place content within the new
    document, appearing to have come from the spoofed
    location. Additionally, if the spoofed document was
    created by a document with a valid SSL certificate, the
    SSL indicators would be carried over into the spoofed
    document. An attacker could use these issues to display
    misleading location and SSL information for a malicious
    web page. (MFSA 2009-44 / CVE-2009-2654)

  - The browser engine in Mozilla Firefox before 3.0.13, and
    3.5.x before 3.5.2, allows remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly execute arbitrary code via vectors
    related to the TraceRecorder::snapshot function in
    js/src/jstracer.cpp, and unspecified other vectors.
    (MFSA 2009-45 / CVE-2009-2662)

  - libvorbis before r16182, as used in Mozilla Firefox
    before 3.0.13 and 3.5.x before 3.5.2 and other products,
    allows context-dependent attackers to cause a denial of
    service (memory corruption and application crash) or
    possibly execute arbitrary code via a crafted .ogg file.
    (CVE-2009-2663 / MFSA 2009-45)

  - The js_watch_set function in js/src/jsdbgapi.cpp in the
    JavaScript engine in Mozilla Firefox before 3.0.13, and
    3.5.x before 3.5.2, allows remote attackers to cause a
    denial of service (assertion failure and application
    exit) or possibly execute arbitrary code via a crafted
    .js file, related to a 'memory safety bug.'.
    (CVE-2009-2664 / MFSA 2009-45)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-44.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-45.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2654.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2662.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2663.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2664.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6433.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-3.0.13-0.4")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-branding-SLED-3.0.3-7.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-translations-3.0.13-0.4")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"firefox3-atk-1.12.3-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"firefox3-cairo-1.2.4-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"firefox3-glib2-2.12.4-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"firefox3-gtk2-2.10.6-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"firefox3-pango-1.14.5-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner190-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner190-translations-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"firefox3-atk-32bit-1.12.3-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"firefox3-cairo-32bit-1.2.4-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"firefox3-glib2-32bit-2.12.4-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"firefox3-gtk2-32bit-2.10.6-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"firefox3-pango-32bit-1.14.5-0.4.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-3.0.13-0.4")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-branding-SLED-3.0.3-7.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-translations-3.0.13-0.4")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"firefox3-atk-1.12.3-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"firefox3-cairo-1.2.4-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"firefox3-glib2-2.12.4-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"firefox3-gtk2-2.10.6-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"firefox3-pango-1.14.5-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner190-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner190-translations-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"firefox3-atk-32bit-1.12.3-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"firefox3-cairo-32bit-1.2.4-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"firefox3-glib2-32bit-2.12.4-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"firefox3-gtk2-32bit-2.10.6-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"firefox3-pango-32bit-1.14.5-0.4.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.13-1.4")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.13-1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
