#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0301 and 
# Oracle Linux Security Advisory ELSA-2016-0301 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(89064);
  script_version("$Revision: 2.21 $");
  script_cvs_date("$Date: 2016/12/07 21:08:16 $");

  script_cve_id("CVE-2015-3197", "CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0800");
  script_osvdb_id(133715, 135121, 135149, 135150, 135151);
  script_xref(name:"RHSA", value:"2016:0301");

  script_name(english:"Oracle Linux 6 / 7 : openssl (ELSA-2016-0301) (DROWN)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0301 :

Updated openssl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A padding oracle flaw was found in the Secure Sockets Layer version
2.0 (SSLv2) protocol. An attacker can potentially use this flaw to
decrypt RSA-encrypted cipher text from a connection using a newer
SSL/TLS protocol version, allowing them to decrypt such connections.
This cross-protocol attack is publicly referred to as DROWN.
(CVE-2016-0800)

Note: This issue was addressed by disabling the SSLv2 protocol by
default when using the 'SSLv23' connection methods, and removing
support for weak SSLv2 cipher suites. For more information, refer to
the knowledge base article linked to in the References section.

A flaw was found in the way malicious SSLv2 clients could negotiate
SSLv2 ciphers that have been disabled on the server. This could result
in weak SSLv2 ciphers being used for SSLv2 connections, making them
vulnerable to man-in-the-middle attacks. (CVE-2015-3197)

A side-channel attack was found that makes use of cache-bank conflicts
on the Intel Sandy-Bridge microarchitecture. An attacker who has the
ability to control code in a thread running on the same hyper-threaded
core as the victim's thread that is performing decryption, could use
this flaw to recover RSA private keys. (CVE-2016-0702)

A double-free flaw was found in the way OpenSSL parsed certain
malformed DSA (Digital Signature Algorithm) private keys. An attacker
could create specially crafted DSA private keys that, when processed
by an application compiled against OpenSSL, could cause the
application to crash. (CVE-2016-0705)

An integer overflow flaw, leading to a NULL pointer dereference or a
heap-based memory corruption, was found in the way some BIGNUM
functions of OpenSSL were implemented. Applications that use these
functions with large untrusted input could crash or, potentially,
execute arbitrary code. (CVE-2016-0797)

Red Hat would like to thank the OpenSSL project for reporting these
issues. Upstream acknowledges Nimrod Aviram and Sebastian Schinzel as
the original reporters of CVE-2016-0800 and CVE-2015-3197; Adam
Langley (Google/BoringSSL) as the original reporter of CVE-2016-0705;
Yuval Yarom (University of Adelaide and NICTA), Daniel Genkin
(Technion and Tel Aviv University), Nadia Heninger (University of
Pennsylvania) as the original reporters of CVE-2016-0702; and Guido
Vranken as the original reporter of CVE-2016-0797.

All openssl users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library must
be restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-March/005831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-March/005832.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"openssl-1.0.1e-42.el6_7.4")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-devel-1.0.1e-42.el6_7.4")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-perl-1.0.1e-42.el6_7.4")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-static-1.0.1e-42.el6_7.4")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-1.0.1e-51.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-51.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-51.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-51.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-51.el7_2.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-libs / openssl-perl / etc");
}
