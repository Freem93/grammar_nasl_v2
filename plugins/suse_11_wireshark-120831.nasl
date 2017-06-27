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
  script_id(64231);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2012-4048", "CVE-2012-4049", "CVE-2012-4285", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291", "CVE-2012-4292", "CVE-2012-4293", "CVE-2012-4296");

  script_name(english:"SuSE 11.2 Security Update : wireshark (SAT Patch Number 6760)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"wireshark was updated to 1.4.15 to fix multiple security issues.

Issues fixed :

  - fix bnc#776038(CVE-2012-4285 / CVE-2012-4288 /
    CVE-2012-4289 / CVE-2012-4296 / CVE-2012-4291 /
    CVE-2012-4292 / CVE-2012-4293 / CVE-2012-4290),
    bnc#772738 (CVE-2012-4048 / CVE-2012-4049)(fixed
    upstream)

  - Security fixes :

  - wnpa-sec-2012-13 The DCP ETSI dissector could trigger a
    zero division. Reported by Laurent Butti. (Bug 7566)

  - wnpa-sec-2012-15 The XTP dissector could go into an
    infinite loop. Reported by Ben Schmidt. (Bug 7571)

  - wnpa-sec-2012-17 The AFP dissector could go into a large
    loop. Reported by Stefan Cornelius. (Bug 7603)

  - wnpa-sec-2012-18 The RTPS2 dissector could overflow a
    buffer. Reported by Laurent Butti. (Bug 7568)

  - wnpa-sec-2012-20 The CIP dissector could exhaust system
    memory. Reported y Ben Schmidt. (Bug 7570)

  - wnpa-sec-2012-21 The STUN dissector could crash.
    Reported by Laurent Butti. (Bug 7569)

  - wnpa-sec-2012-22 The EtherCAT Mailbox dissector could
    abort. Reported by Laurent Butti. (Bug 7562)

  - wnpa-sec-2012-23 The CTDB dissector could go into a
    large loop. Reported by Ben Schmidt. (Bug 7573)

  - Bug fixes :

  - Wireshark crashes on opening very short NFS pcap file.
    (Bug 7498)

  - Updated Protocol Support

  - AFP, Bluetooth L2CAP, CIP, CTDB, DCP ETSI, EtherCAT
    Mailbox, FC Link Control LISP, NFS, RTPS2, SCTP, STUN,
    XTP"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4285.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4288.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4289.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4290.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4291.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4292.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4293.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4296.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6760.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"wireshark-1.4.15-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"wireshark-1.4.15-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"wireshark-1.4.15-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
