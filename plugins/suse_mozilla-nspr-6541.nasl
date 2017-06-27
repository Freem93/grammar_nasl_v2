#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42190);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408");

  script_name(english:"SuSE 10 Security Update : Mozilla NSS (ZYPP Patch Number 6541)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
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
    value:"http://support.novell.com/security/cve/CVE-2009-2404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2408.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6541.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/20");
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
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nspr-4.8-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nspr-devel-4.8-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nss-3.12.3.1-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nss-devel-3.12.3.1-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nss-tools-3.12.3.1-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.8-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.3.1-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nspr-4.8-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nspr-devel-4.8-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nss-3.12.3.1-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nss-devel-3.12.3.1-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.8-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.3.1-1.4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
