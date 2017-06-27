#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200912-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(42968);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1387", "CVE-2009-2409", "CVE-2009-3555");
  script_bugtraq_id(35001, 35138, 35417, 36935);
  script_osvdb_id(54612, 54613, 54614, 55072, 56752, 59968, 59969, 59970, 59971, 59972, 59974, 60521, 61234, 61718);
  script_xref(name:"GLSA", value:"200912-01");

  script_name(english:"GLSA-200912-01 : OpenSSL: Multiple vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200912-01
(OpenSSL: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in OpenSSL:
    Marsh Ray of PhoneFactor and Martin Rex of SAP independently
    reported that the TLS protocol does not properly handle session
    renegotiation requests (CVE-2009-3555).
    The MD2 hash algorithm is no longer considered to be
    cryptographically strong, as demonstrated by Dan Kaminsky. Certificates
    using this algorithm are no longer accepted (CVE-2009-2409).
    Daniel Mentz and Robin Seggelmann reported the following
    vulnerabilities related to DTLS: A use-after-free flaw (CVE-2009-1379)
    and a NULL pointer dereference (CVE-2009-1387) in the
    dtls1_retrieve_buffered_fragment() function in src/d1_both.c, multiple
    memory leaks in the dtls1_process_out_of_seq_message() function in
    src/d1_both.c (CVE-2009-1378), and a processing error related to a
    large amount of DTLS records with a future epoch in the
    dtls1_buffer_record() function in ssl/d1_pkt.c
    (CVE-2009-1377).
  
Impact :

    A remote unauthenticated attacker, acting as a Man in the Middle, could
    inject arbitrary plain text into a TLS session, possibly leading to the
    ability to send requests as if authenticated as the victim. A remote
    attacker could furthermore send specially crafted DTLS packages to a
    service using OpenSSL for DTLS support, possibly resulting in a Denial
    of Service. Also, a remote attacker might be able to create rogue
    certificates, facilitated by a MD2 collision. NOTE: The amount of
    computation needed for this attack is still very large.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200912-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/openssl-0.9.8l-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 0.9.8l-r2"), vulnerable:make_list("lt 0.9.8l-r2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenSSL");
}
