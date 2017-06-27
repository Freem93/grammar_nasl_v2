#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:059. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(81942);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/19 15:24:54 $");

  script_cve_id("CVE-2014-1492", "CVE-2014-1544", "CVE-2014-1545", "CVE-2014-1568", "CVE-2014-1569");
  script_xref(name:"MDVSA", value:"2015:059");

  script_name(english:"Mandriva Linux Security Advisory : nss (MDVSA-2015:059)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in the Mozilla
NSS and NSPR packages :

The cert_TestHostName function in lib/certdb/certdb.c in the
certificate-checking implementation in Mozilla Network Security
Services (NSS) before 3.16 accepts a wildcard character that is
embedded in an internationalized domain name's U-label, which might
allow man-in-the-middle attackers to spoof SSL servers via a crafted
certificate (CVE-2014-1492).

Use-after-free vulnerability in the CERT_DestroyCertificate function
in libnss3.so in Mozilla Network Security Services (NSS) 3.x, as used
in Firefox before 31.0, Firefox ESR 24.x before 24.7, and Thunderbird
before 24.7, allows remote attackers to execute arbitrary code via
vectors that trigger certain improper removal of an NSSCertificate
structure from a trust domain (CVE-2014-1544).

Mozilla Network Security Services (NSS) before 3.16.2.1, 3.16.x before
3.16.5, and 3.17.x before 3.17.1, as used in Mozilla Firefox before
32.0.3, Mozilla Firefox ESR 24.x before 24.8.1 and 31.x before 31.1.1,
Mozilla Thunderbird before 24.8.1 and 31.x before 31.1.2, Mozilla
SeaMonkey before 2.29.1, Google Chrome before 37.0.2062.124 on Windows
and OS X, and Google Chrome OS before 37.0.2062.120, does not properly
parse ASN.1 values in X.509 certificates, which makes it easier for
remote attackers to spoof RSA signatures via a crafted certificate,
aka a signature malleability issue (CVE-2014-1568).

The definite_length_decoder function in lib/util/quickder.c in Mozilla
Network Security Services (NSS) before 3.16.2.4 and 3.17.x before
3.17.3 does not ensure that the DER encoding of an ASN.1 length is
properly formed, which allows remote attackers to conduct
data-smuggling attacks by using a long byte sequence for an encoding,
as demonstrated by the SEC_QuickDERDecodeItem function's improper
handling of an arbitrary-length encoding of 0x00 (CVE-2014-1569).

Mozilla Netscape Portable Runtime (NSPR) before 4.10.6 allows remote
attackers to execute arbitrary code or cause a denial of service
(out-of-bounds write) via vectors involving the sprintf and console
functions (CVE-2014-1545).

The sqlite3 packages have been upgraded to the 3.8.6 version due to an
prerequisite to nss-3.17.x.

Additionally the rootcerts package has also been updated to the latest
version as of 2014-11-17, which adds, removes, and distrusts several
certificates.

The updated packages provides a solution for these security issues."
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.16.1_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b157b539"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.16.2_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9bc9e12"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.16.3_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0ee8a6e"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.16_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37a5d820"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.17.1_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10a22496"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.17.2_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d0a4a5b"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.17.3_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d78ddde"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.17.4_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cabce5f"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.17_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ce2e69d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-55/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sqlite3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sqlite3-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64sqlite3_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sqlite3-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sqlite3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lemon-3.8.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64nspr-devel-4.10.8-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64nspr4-4.10.8-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64nss-devel-3.17.4-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64nss-static-devel-3.17.4-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64nss3-3.17.4-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64sqlite3-devel-3.8.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64sqlite3-static-devel-3.8.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64sqlite3_0-3.8.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"nss-3.17.4-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"nss-doc-3.17.4-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"rootcerts-20141117.00-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"rootcerts-java-20141117.00-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"sqlite3-tcl-3.8.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"sqlite3-tools-3.8.6-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
