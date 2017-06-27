#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87564);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2014-9297", "CVE-2014-9298", "CVE-2014-9750", "CVE-2014-9751", "CVE-2015-1798", "CVE-2015-1799", "CVE-2015-3405");

  script_name(english:"Scientific Linux Security Update : ntp on SL7.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that because NTP's access control was based on a source
IP address, an attacker could bypass source IP restrictions and send
malicious control and configuration packets by spoofing ::1 addresses.
(CVE-2014-9298, CVE-2014-9751)

A denial of service flaw was found in the way NTP hosts that were
peering with each other authenticated themselves before updating their
internal state variables. An attacker could send packets to one peer
host, which could cascade to other peers, and stop the synchronization
process among the reached peers. (CVE-2015-1799)

A flaw was found in the way the ntp-keygen utility generated MD5
symmetric keys on big-endian systems. An attacker could possibly use
this flaw to guess generated MD5 keys, which could then be used to
spoof an NTP client or server. (CVE-2015-3405)

A stack-based buffer overflow was found in the way the NTP autokey
protocol was implemented. When an NTP client decrypted a secret
received from an NTP server, it could cause that client to crash.
(CVE-2014-9297, CVE-2014-9750)

It was found that ntpd did not check whether a Message Authentication
Code (MAC) was present in a received packet when ntpd was configured
to use symmetric cryptographic keys. A man-in-the-middle attacker
could use this flaw to send crafted packets that would be accepted by
a client or a peer without the attacker knowing the symmetric key.
(CVE-2015-1798)

Bug fixes :

  - The ntpd service truncated symmetric keys specified in
    the key file to 20 bytes. As a consequence, it was
    impossible to configure NTP authentication to work with
    peers that use longer keys. With this update, the
    maximum key length has been changed to 32 bytes.

  - The ntpd service could previously join multicast groups
    only when starting, which caused problems if ntpd was
    started during system boot before network was
    configured. With this update, ntpd attempts to join
    multicast groups every time network configuration is
    changed.

  - Previously, the ntp-keygen utility used the exponent of
    3 when generating RSA keys. Consequently, generating RSA
    keys failed when FIPS mode was enabled. With this
    update, ntp-keygen has been modified to use the exponent
    of 65537, and generating keys in FIPS mode now works as
    expected.

  - The ntpd service dropped incoming NTP packets if their
    source port was lower than 123 (the NTP port). With this
    update, ntpd no longer checks the source port number,
    and clients behind NAT are now able to correctly
    synchronize with the server.

Enhancements :

  - This update adds support for configurable Differentiated
    Services Code Points (DSCP) in NTP packets, simplifying
    configuration in large networks where different NTP
    implementations or versions are using different DSCP
    values.

  - This update adds the ability to configure separate clock
    stepping thresholds for each direction (backward and
    forward). Use the 'stepback' and 'stepfwd' options to
    configure each threshold.

  - Support for nanosecond resolution has been added to the
    Structural Health Monitoring (SHM) reference clock.
    Prior to this update, when a Precision Time Protocol
    (PTP) hardware clock was used as a time source to
    synchronize the system clock, the accuracy of the
    synchronization was limited due to the microsecond
    resolution of the SHM protocol. The nanosecond extension
    in the SHM protocol now allows sub-microsecond
    synchronization of the system clock."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=9091
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c289de2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-4.2.6p5-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-22.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-doc-4.2.6p5-22.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-perl-4.2.6p5-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sntp-4.2.6p5-22.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
