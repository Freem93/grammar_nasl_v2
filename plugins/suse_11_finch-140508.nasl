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
  script_id(74173);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/05/25 00:10:17 $");

  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6486", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");

  script_name(english:"SuSE 11.3 Security Update : finch (SAT Patch Number 9213)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The pidgin Instant Messenger has been updated to fix various security
issues :

  - Remotely triggerable crash in IRC argument parsing.
    (CVE-2014-0020)

  - Buffer overflow in SIMPLE header parsing.
    (CVE-2013-6490)

  - Buffer overflow in MXit emoticon parsing.
    (CVE-2013-6489)

  - Buffer overflow in Gadu-Gadu HTTP parsing.
    (CVE-2013-6487)

  - Pidgin uses clickable links to untrusted executables.
    (CVE-2013-6486)

  - Buffer overflow parsing chunked HTTP responses.
    (CVE-2013-6485)

  - Crash reading response from STUN server. (CVE-2013-6484)

  - XMPP doesn't verify 'from' on some iq replies.
    (CVE-2013-6483)

  - NULL pointer dereference parsing SOAP data in MSN.
    (CVE-2013-6482)

  - NULL pointer dereference parsing OIM data in MSN.
    (CVE-2013-6482)

  - NULL pointer dereference parsing headers in MSN.
    (CVE-2013-6482)

  - Remote crash reading Yahoo! P2P message. (CVE-2013-6481)

  - Remote crash parsing HTTP responses. (CVE-2013-6479)

  - Crash when hovering pointer over a long URL.
    (CVE-2013-6478)

  - Crash handling bad XMPP timestamp. (CVE-2013-6477)

  - Yahoo! remote crash from incorrect character encoding.
    (CVE-2012-6152)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6152.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6481.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6489.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6490.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0020.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9213.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/24");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"finch-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpurple-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpurple-lang-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpurple-meanwhile-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpurple-tcl-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pidgin-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"finch-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpurple-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpurple-lang-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpurple-meanwhile-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpurple-tcl-2.6.6-0.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pidgin-2.6.6-0.23.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
