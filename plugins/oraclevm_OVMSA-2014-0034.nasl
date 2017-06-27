#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0034.
#

include("compat.inc");

if (description)
{
  script_id(79549);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2002-2443", "CVE-2012-1016", "CVE-2013-1415", "CVE-2013-1416", "CVE-2013-1418", "CVE-2013-6800", "CVE-2014-4341", "CVE-2014-4342", "CVE-2014-4343", "CVE-2014-4344", "CVE-2014-4345");
  script_bugtraq_id(58144, 58532, 59261, 60008, 63555, 63770, 68908, 68909, 69159, 69160, 69168);
  script_osvdb_id(93240, 99508, 108748, 108751, 109389, 109390, 109908);

  script_name(english:"OracleVM 3.3 : krb5 (OVMSA-2014-0034)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - actually apply that last patch

  - incorporate fix for MITKRB5-SA-2014-001 (CVE-2014-4345,
    #1128157)

  - ksu: when evaluating .k5users, don't throw away data
    from .k5users when we're not passed a command to run,
    which implicitly means we're attempting to run the
    target user's shell (#1026721, revised)

  - ksu: when evaluating .k5users, treat lines with just a
    principal name as if they contained the principal name
    followed by '*', and don't throw away data from .k5users
    when we're not passed a command to run, which implicitly
    means we're attempting to run the target user's shell
    (#1026721, revised)

  - gssapi: pull in upstream fix for a possible NULL
    dereference in spnego (CVE-2014-4344, #1121510)

  - gssapi: pull in proposed-and-accepted fix for a double
    free in initiators (David Woodhouse, CVE-2014-4343,
    #1121510)

  - correct a type mistake in the backported fix for
    (CVE-2013-1418, CVE-2013-6800)

  - pull in backported fix for denial of service by
    injection of malformed GSSAPI tokens (CVE-2014-4341,
    CVE-2014-4342, #1121510)

  - incorporate backported patch for remote crash of KDCs
    which serve multiple realms simultaneously (RT#7756,
    CVE-2013-1418/CVE-2013-6800, more of

  - pull in backport of patch to not subsequently always
    require that responses come from master KDCs if we get
    one from a master somewhere along the way while chasing
    referrals (RT#7650, #1113652)

  - ksu: if the -e flag isn't used, use the target user's
    shell when checking for authorization via the target
    user's .k5users file (#1026721)

  - define _GNU_SOURCE in files where we use EAI_NODATA, to
    make sure that it's declared (#1059730)

  - spnego: pull in patch from master to restore preserving
    the OID of the mechanism the initiator requested when we
    have multiple OIDs for the same mechanism, so that we
    reply using the same mechanism OID and the initiator
    doesn't get confused (#1087068, RT#7858)

  - add patch from Jatin Nansi to avoid attempting to clear
    memory at the NULL address if krb5_encrypt_helper
    returns an error when called from encrypt_credencpart
    (#1055329, pull #158)

  - drop patch to add additional access checks to ksu - they
    shouldn't be resulting in any benefit

  - apply patch from Nikolai Kondrashov to pass a default
    realm set in /etc/sysconfig/krb5kdc to the
    kdb_check_weak helper, so that it doesn't produce an
    error if there isn't one set in krb5.conf (#1009389)

  - packaging: don't Obsoletes: older versions of
    krb5-pkinit-openssl and virtual Provide:
    krb5-pkinit-openssl on EL6, where we don't need to
    bother with any of that (#1001961)

  - pkinit: backport tweaks to avoid trying to call the
    prompter callback when one isn't set (part of #965721)

  - pkinit: backport the ability to use a prompter callback
    to prompt for a password when reading private keys (the
    rest of #965721)

  - backport fix to not spin on a short read when reading
    the length of a response over TCP (RT#7508, #922884)

  - backport fix for trying all compatible keys when not
    being strict about acceptor names while reading AP-REQs
    (RT#7883, #1070244)

  - backport fix for not being able to verify the list of
    transited realms in GSS acceptors (RT#7639, #959685)

  - pull fix for keeping track of the message type when
    parsing FAST requests in the KDC (RT#7605, #951965)

  - incorporate upstream patch to fix a NULL pointer
    dereference while processing certain TGS requests
    (CVE-2013-1416, #950343)

  - incorporate upstream patch to fix a NULL pointer
    dereference when the client supplies an
    otherwise-normal-looking PKINIT request (CVE-2013-1415,
    #917910)

  - add patch to avoid dereferencing a NULL pointer in the
    KDC when handling a draft9 PKINIT request (#917910,
    CVE-2012-1016)

  - pull up fix for UDP ping-pong flaw in kpasswd service
    (CVE-2002-2443, 

  - don't leak the memory used to hold the previous entry
    when walking a keytab to figure out which kinds of keys
    we have (#911147)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-November/000234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dbf93cd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected krb5-libs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/04");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"krb5-libs-1.10.3-33.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-libs");
}
