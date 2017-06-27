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
  script_id(77960);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/21 15:59:35 $");

  script_cve_id("CVE-2014-5161", "CVE-2014-5162", "CVE-2014-5163", "CVE-2014-5164", "CVE-2014-5165", "CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6424", "CVE-2014-6427", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432");

  script_name(english:"SuSE 11.3 Security Update : wireshark (SAT Patch Number 9745)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The wireshark package was upgraded to 1.10.10 from 1.8.x as 1.8 was
discontinued.

This update fixes vulnerabilities that could allow an attacker to
crash Wireshark or make it become unresponsive by sending specific
packets onto the network or have them loaded via a capture file while
the dissectors are running. It also contains a number of other bug
fixes.

  - RTP dissector crash. (wnpa-sec-2014-12 CVE-2014-6421 /
    CVE-2014-6422)

  - MEGACO dissector infinite loop. (wnpa-sec-2014-13
    CVE-2014-6423)

  - Netflow dissector crash. (wnpa-sec-2014-14
    CVE-2014-6424)

  - RTSP dissector crash. (wnpa-sec-2014-17 CVE-2014-6427)

  - SES dissector crash. (wnpa-sec-2014-18 CVE-2014-6428)

  - Sniffer file parser crash. (wnpa-sec-2014-19
    CVE-2014-6429 / CVE-2014-6430 / CVE-2014-6431 /
    CVE-2014-6432)

  - The Catapult DCT2000 and IrDA dissectors could underrun
    a buffer. (wnpa-sec-2014-08 CVE-2014-5161 /
    CVE-2014-5162, bnc#889901)

  - The GSM Management dissector could crash.
    (wnpa-sec-2014-09 CVE-2014-5163, bnc#889906)

  - The RLC dissector could crash. (wnpa-sec-2014-10
    CVE-2014-5164, bnc#889900)

  - The ASN.1 BER dissector could crash. (wnpa-sec-2014-11
    CVE-2014-5165, bnc#889899) Further bug fixes as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.10.1
    0.html and
    https://www.wireshark.org/docs/relnotes/wireshark-1.10.9
    .html ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=897055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5161.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5164.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5165.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6427.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6428.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6431.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6432.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9745.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"wireshark-1.10.10-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"wireshark-1.10.10-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"wireshark-1.10.10-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
