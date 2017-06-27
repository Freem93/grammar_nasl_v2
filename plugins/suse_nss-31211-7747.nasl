#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56611);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/05/17 11:20:15 $");

  script_name(english:"SuSE 10 Security Update : Mozilla NSS (ZYPP Patch Number 7747)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update updates Mozilla NSS to 3.12.11.

The update marks the compromised DigiNotar Certificate Authority as
untrusted

For more information read :

  - * update to 3.12.10 o root CA changes o filter certain
    bogus certs (bmo#642815) o fix minor memory leaks o
    other bugfixes. (MFSA 2011-34)

  - update to 3.12.9 o fix minor memory leaks (bmo#619268) o
    fix crash in nss_cms_decoder_work_data (bmo#607058) o
    fix crash in certutil (bmo#620908) o handle invalid
    argument in JPAKE (bmo#609068) o J-PAKE support (API
    requirement for Firefox >= 4.0b8)

  - replaced expired PayPal test certificate (fixing
    testsuite)

  - removed DigiNotar root certifiate from trusted db
    (bmo#682927) This update also brings the prerequired
    Mozilla NSPR to version 4.8.9.

  - update to 4.8.9

  - update to 4.8.8 o support IPv6 on Android (bmo#626866) o
    use AI_ADDRCONFIG for loopback hostnames (bmo#614526) o
    support SDP sockets (bmo#518078) o support m32r
    architecture (bmo#635667) o use atomic functions on ARM
    (bmo#626309) o some other fixes not affecting the Linux
    platform"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-34.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7747.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-nspr-4.8.9-1.5.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-nspr-devel-4.8.9-1.5.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-nss-3.12.11-3.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-nss-devel-3.12.11-3.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-nss-tools-3.12.11-3.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.8.9-1.5.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.11-3.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
