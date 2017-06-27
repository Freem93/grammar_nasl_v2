#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0003.
#

include("compat.inc");

if (description)
{
  script_id(79452);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
  script_bugtraq_id(34257, 34408, 34409);

  script_name(english:"OracleVM 2.1 : krb5 (OVMSA-2009-0003)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

CVE-2009-0844 The get_input_token function in the SPNEGO
implementation in MIT Kerberos 5 (aka krb5) 1.5 through 1.6.3 allows
remote attackers to cause a denial of service (daemon crash) and
possibly obtain sensitive information via a crafted length value that
triggers a buffer over-read.

CVE-2009-0845 The spnego_gss_accept_sec_context function in
lib/gssapi/spnego/spnego_mech.c in MIT Kerberos 5 (aka krb5) 1.5
through 1.6.3, when SPNEGO is used, allows remote attackers to cause a
denial of service (NULL pointer dereference and daemon crash) via
invalid ContextFlags data in the reqFlags field in a negTokenInit
token.

CVE-2009-0846 The asn1_decode_generaltime function in
lib/krb5/asn.1/asn1_decode.c in the ASN.1 GeneralizedTime decoder in
MIT Kerberos 5 (aka krb5) before 1.6.4 allows remote attackers to
cause a denial of service (daemon crash) or possibly execute arbitrary
code via vectors involving an invalid DER encoding that triggers a
free of an uninitialized pointer.

  - update to revised patch for (CVE-2009-0844,
    CVE-2009-0845)

  - add fix for potential buffer read overrun in the SPNEGO
    GSSAPI mechanism (#490635, CVE-2009-0844)

  - add fix for NULL pointer dereference when handling
    certain error cases in the SPNEGO GSSAPI mechanism
    (#490635, CVE-2009-0845)

  - add fix for attempt to free uninitialized pointer in the
    ASN.1 decoder (#490635, CVE-2009-0846)

  - add fix for bug in length validation in the ASN.1
    decoder (CVE-2009-0847)

  - add backport of svn patch to fix a bug in how the gssapi
    library handles certain error cases in
    gss_accept_sec_context (CVE-2009-0845, 

  - add a backported patch which adds a check on credentials
    obtained from a foreign realm to make sure that they're
    of an acceptable type, and if not, retry to the request
    to get one of the right type (Sadique Puthen,

  - backport fix from 1.6.3 to register file-based ccaches
    created with the krb5_cc_new_unique function with the
    global list, so that we don't crash when we go to close
    the ccache (#468729)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2009-April/000019.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bfa7904"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected krb5-libs / krb5-server / krb5-workstation
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "2\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.1", reference:"krb5-libs-1.6.1-31.el5_3.3")) flag++;
if (rpm_check(release:"OVS2.1", reference:"krb5-server-1.6.1-31.el5_3.3")) flag++;
if (rpm_check(release:"OVS2.1", reference:"krb5-workstation-1.6.1-31.el5_3.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-libs / krb5-server / krb5-workstation");
}
