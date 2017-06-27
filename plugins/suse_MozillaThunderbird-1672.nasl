#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaThunderbird-1672.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27124);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2783", "CVE-2006-2786", "CVE-2006-2787");

  script_name(english:"openSUSE 10 Security Update : MozillaThunderbird (MozillaThunderbird-1672)");
  script_summary(english:"Check for the MozillaThunderbird-1672 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of Mozilla Thunderbird fixes the security problems fixed
in version 1.5.0.4: MFSA 2006-31/CVE-2006-2787: EvalInSandbox in
Mozilla Firefox and Thunderbird before 1.5.0.4 allows remote attackers
to gain privileges via JavaScript that calls the valueOf method on
objects that were created outside of the sandbox. MFSA
2006-32/CVE-2006-2780: Integer overflow in Mozilla Firefox and
Thunderbird before 1.5.0.4 allows remote attackers to cause a denial
of service (crash) and possibly execute arbitrary code via 'jsstr
tagify,' which leads to memory corruption. MFSA 2006-32/CVE-2006-2779:
Mozilla Firefox and Thunderbird before 1.5.0.4 allow remote attackers
to cause a denial of service (crash) and possibly execute arbitrary
code via (1) nested <option> tags in a select tag, (2) a
DOMNodeRemoved mutation event, (3) 'Content-implemented tree views,'
(4) BoxObjects, (5) the XBL implementation, (6) an iframe that
attempts to remove itself, which leads to memory corruption. MFSA
2006-33/CVE-2006-2786: HTTP response smuggling vulnerability in
Mozilla Firefox and Thunderbird before 1.5.0.4, when used with certain
proxy servers, allows remote attackers to cause Firefox to interpret
certain responses as if they were responses from two different sites
via (1) invalid HTTP response headers with spaces between the header
name and the colon, which might not be ignored in some cases, or (2)
HTTP 1.1 headers through an HTTP 1.0 proxy, which are ignored by the
proxy but processed by the client. MFSA 2006-35/CVE-2006-2775: Mozilla
Firefox and Thunderbird before 1.5.0.4 associates XUL attributes with
the wrong URL under certain unspecified circumstances, which might
allow remote attackers to bypass restrictions by causing a persisted
string to be associated with the wrong URL. MFSA
2006-37/CVE-2006-2776: Certain privileged UI code in Mozilla Firefox
and Thunderbird before 1.5.0.4 calls content-defined setters on an
object prototype, which allows remote attackers to execute code at a
higher privilege than intended. MFSA 2006-38/CVE-2006-2778: The
crypto.signText function in Mozilla Firefox and Thunderbird before
1.5.0.4 allows remote attackers to execute arbitrary code via certain
optional Certificate Authority name arguments, which causes an invalid
array index and triggers a buffer overflow. MFSA
2006-40/CVE-2006-2781: Double-free vulnerability in Mozilla
Thunderbird before 1.5.0.4 and SeaMonkey before 1.0.2 allows remote
attackers to cause a denial of service (hang) and possibly execute
arbitrary code via a VCard that contains invalid base64 characters.
MFSA 2006-42/CVE-2006-2783: Mozilla Firefox and Thunderbird before
1.5.0.4 strips the Unicode Byte-order-Mark (BOM) from a UTF-8 page
before the page is passed to the parser, which allows remote attackers
to conduct cross-site scripting (XSS) attacks via a BOM sequence in
the middle of a dangerous tag such as SCRIPT."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"MozillaThunderbird-1.5.0.4-2.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"MozillaThunderbird-translations-1.5.0.4-2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Thunderbird");
}
