#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29359);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0995", "CVE-2007-0996");

  script_name(english:"SuSE 10 Security Update : MozillaFirefox (ZYPP Patch Number 2683)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to security update version
1.5.0.10.

  - As part of the Firefox 2.0.0.2 and 1.5.0.10 update
    releases several bugs were fixed to improve the
    stability of the browser. Some of these were crashes
    that showed evidence of memory corruption and we presume
    that with enough effort at least some of these could be
    exploited to run arbitrary code. These fixes affected
    the layout engine (CVE-2007-0775), SVG renderer
    (CVE-2007-0776) and JavaScript engine. (CVE-2007-0777).
    (MFSA 2007-01)

  - Various enhancements were done to make XSS exploits
    against websites less effective. These included fixes
    for invalid trailing characters (CVE-2007-0995), child
    frame character set inheritance (CVE-2007-0996),
    password form injection (CVE-2006-6077), and the Adobe
    Reader universal XSS problem. (MFSA 2007-02)

  - AAd reported a potential disk cache collision that could
    be exploited by remote attackers to steal confidential
    data or execute code. (MFSA 2007-03 / CVE-2007-0778)

  - David Eckel reported that browser UI elements--such as
    the host name and security indicators--could be spoofed
    by using a large, mostly transparent, custom cursor and
    adjusting the CSS3 hotspot property so that the visible
    part of the cursor floated outside the browser content
    area. (MFSA 2007-04 / CVE-2007-0779)

  - Manually opening blocked popups could be exploited by
    remote attackers to allow XSS attacks (CVE-2007-0780) or
    to execute code in local files. (CVE-2007-0800). (MFSA
    2007-05)

  - Two buffer overflows were found in the NSS handling of
    Mozilla. (MFSA 2007-06)

  - SSL clients such as Firefox and Thunderbird can suffer a
    buffer overflow if a malicious server presents a
    certificate with a public key that is too small to
    encrypt the entire 'Master Secret'. Exploiting this
    overflow appears to be unreliable but possible if the
    SSLv2 protocol is enabled. (CVE-2007-0008)

  - Servers that use NSS for the SSLv2 protocol can be
    exploited by a client that presents a 'Client Master
    Key' with invalid length values in any of several fields
    that are used without adequate error checking. This can
    lead to a buffer overflow that presumably could be
    exploitable. (CVE-2007-0009)

  - Michal Zalewski demonstrated that setting
    location.hostname to a value with embedded null
    characters can confuse the browsers domain checks.
    Setting the value triggers a load, but the networking
    software reads the hostname only up to the null
    character while other checks for 'parent domain' start
    at the right and so can have a completely different idea
    of what the current host is. (MFSA 2007-06 /
    CVE-2007-0981)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-04.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-06.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-6077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0778.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0779.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0780.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0995.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0996.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2683.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:0, reference:"MozillaFirefox-1.5.0.10-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:0, reference:"MozillaFirefox-translations-1.5.0.10-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"MozillaFirefox-1.5.0.10-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"MozillaFirefox-translations-1.5.0.10-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
