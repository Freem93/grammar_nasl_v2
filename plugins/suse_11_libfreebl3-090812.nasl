#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41419);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408");

  script_name(english:"SuSE 11 Security Update : Mozilla Firefox (SAT Patch Number 1199)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla NSS security framework was updated to version 3.12.3.1.

  - Heap-based buffer overflow in a regular-expression
    parser in Mozilla Network Security Services (NSS) before
    3.12.3, as used in Firefox, Thunderbird, SeaMonkey,
    Evolution, Pidgin, and AOL Instant Messenger (AIM),
    allows remote SSL servers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a long domain name in the subject's Common Name (CN)
    field of an X.509 certificate, related to the
    cert_TestHostName function. (CVE-2009-2404 / MFSA
    2009-43)

  - IOActive security researcher Dan Kaminsky reported a
    mismatch in the treatment of domain names in SSL
    certificates between SSL clients and the Certificate
    Authorities (CA) which issue server certificates. In
    particular, if a malicious person requested a
    certificate for a host name with an invalid null
    character in it most CAs would issue the certificate if
    the requester owned the domain specified after the null,
    while most SSL clients (browsers) ignored that part of
    the name and used the unvalidated part in front of the
    null. This made it possible for attackers to obtain
    certificates that would function for any site they
    wished to target. These certificates could be used to
    intercept and potentially alter encrypted communication
    between the client and a server such as sensitive bank
    account transactions. This vulnerability was
    independently reported to us by researcher Moxie
    Marlinspike who also noted that since Firefox relies on
    SSL to protect the integrity of security updates this
    attack could be used to serve malicious updates. (MFSA
    2009-42 / CVE-2009-2408)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-43.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2408.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1199.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libfreebl3-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-nss-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-nss-tools-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libfreebl3-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libfreebl3-32bit-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-nss-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-nss-tools-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libfreebl3-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-nss-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-nss-tools-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libfreebl3-32bit-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"mozilla-nss-32bit-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libfreebl3-32bit-3.12.3.1-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.3.1-1.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
