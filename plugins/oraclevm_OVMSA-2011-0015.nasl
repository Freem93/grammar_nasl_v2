#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2011-0015.
#

include("compat.inc");

if (description)
{
  script_id(79475);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2009-4212", "CVE-2010-0629", "CVE-2010-1321", "CVE-2010-1323", "CVE-2011-0281", "CVE-2011-0282", "CVE-2011-4862");
  script_bugtraq_id(37749, 39247, 40235, 45118, 46265, 46271, 51182);

  script_name(english:"OracleVM 2.2 : krb5 (OVMSA-2011-0015)");
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

  - Fix for (CVE-2011-4862)

  - incorporate a fix to teach the file labeling bits about
    when replay caches are expunged (#712453)

  - rebuild

  - ftp: handle larger command inputs (#665833)

  - don't bail halfway through an unlock operation when the
    result will be discarded and the end-result not cleaned
    up (Martin Osvald, #586032)

  - add a versioned dependency between krb5-server-ldap and
    krb5-libs (internal tooling)

  - don't discard the error code from an error message
    received in response to a change-password request
    (#658871, RT#6893)

  - ftpd: add patch from Jatin Nansi to correctly match
    restrict lines in /etc/ftpusers (#644215, RT#6889)

  - ftp: add modified patch from Rogan Kyuseok Lee to report
    the number of bytes transferred correctly when
    transferring large files on 32-bit systems (#648404)

  - backport fix for RT#6514: memory leak freeing rcache
    type none (#678205)

  - add upstream patch to fix hang or crash in the KDC when
    using the LDAP kdb backend (CVE-2011-0281,
    CVE-2011-0282, #671097)

  - incorporate upstream patch for checksum acceptance
    issues from MITKRB5-SA-2010-007 (CVE-2010-1323, #652308)

  - backport a fix to the previous change (#539423)

  - backport the k5login_directory and k5login_authoritative
    settings (#539423)

  - krshd: don't limit user names to 16 chars when utmp can
    handle names at least a bit longer than that (#611713)

  - fix a logic bug in computing key expiration times
    (RT#6762, #627038)

  - correct the post-rotate scriptlet in the kadmind
    logrotate config (more of #462658)

  - ftpd: backport changes to modify behavior to match
    telnetd,rshd,rlogind and accept GSSAPI auth to any
    service for which we have a matching key (#538075)

  - pull in fix for RT#5551 to treat the referral realm when
    seen in a ticket as though it were the local realm
    (#498554, also very likely #450122)

  - add aes256-cts:normal and aes128-cts:normal to the list
    of keysalts in the default kdc.conf (part of #565941)

  - add a note to kdc.conf(5) pointing to the admin guide
    for the list of recognized key and salt types (the rest
    of #565941)

  - add logrotate configuration files for krb5kdc and
    kadmind (#462658)

  - libgssapi: backport patch from svn to stop returning
    context-expired errors when the ticket which was used to
    set up the context expires (#605367, upstream #6739)

  - enable building the -server-ldap subpackage (#514362)

  - stop caring about the endianness of stash files
    (#514741), which will be replaced by proper keytab files
    in later releases

  - don't crash in krb5_get_init_creds_password if the
    passed-in options struct is NULL and the clients keys
    have expired (#555875)

  - ksu: perform PAM account and session management before
    dropping privileges to those of the target user (#540769
    and #596887, respectively)

  - add candidate patch to correct libgssapi null pointer
    dereference which could be triggered by malformed client
    requests (CVE-2010-1321, #583704)

  - fix a null pointer dereference and crash introduced in
    our PAM patch that would happen if ftpd was given the
    name of a user who wasnt known to the local system,
    limited to being triggerable by gssapi-authenticated
    clients by the default xinetd config (Olivier Fourdan,
    #569472)

  - add upstream patch to fix a few use-after-free bugs,
    including one in kadmind (CVE-2010-0629, #578186)

  - merge patch to correct KDC integer overflows which could
    be triggered by malformed RC4 and AES ciphertexts
    (CVE-2009-4212, #546348)

  - pull changes to libkrb5 to properly handle and chase
    off-path referrals back from 1.7 (#546538)

  - add an auth stack to ksus PAM configuration so that it
    can successfully pam_setcred

  - also set PAM_RUSER in ksu for completeness
    (#479071+#477033)

  - fix various typos, except for bits pertaining to
    licensing (#499190)

  - kdb5_util: when renaming a database, if the new names
    associated lock files don't exist, go ahead and create
    them (#442879)

  - ksu: perform PAM account and session management for the
    target user  authentication is still performed as before
    (#477033)

  - fix typo in ksus reporting of errors getting credentials
    (#462890)

  - kadmind.init: stop setting up a keytab, as kadminds been
    able to use the database directly for a while now
    (#473151)

  - pull up patch to set PAM_RHOST (James Leddy, #479071)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2012-January/000064.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?783bc3a1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected krb5-libs / krb5-workstation packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/04");
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
if (! ereg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"krb5-libs-1.6.1-63.el5_7")) flag++;
if (rpm_check(release:"OVS2.2", reference:"krb5-workstation-1.6.1-63.el5_7")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-libs / krb5-workstation");
}
