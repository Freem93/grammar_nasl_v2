#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1459 and 
# CentOS Errata and Security Advisory 2015:1459 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85025);
  script_version("$Revision: 2.20 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2014-9297", "CVE-2014-9298", "CVE-2014-9750", "CVE-2014-9751", "CVE-2015-1798", "CVE-2015-1799", "CVE-2015-3405");
  script_osvdb_id(116071, 116072, 120350, 120351, 120524);
  script_xref(name:"RHSA", value:"2015:1459");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"CentOS 6 : ntp (CESA-2015:1459)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ntp packages that fix multiple security issues, several bugs,
and add two enhancements are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with another referenced time source.

It was found that because NTP's access control was based on a source
IP address, an attacker could bypass source IP restrictions and send
malicious control and configuration packets by spoofing ::1 addresses.
(CVE-2014-9298)

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
(CVE-2014-9297)

It was found that ntpd did not check whether a Message Authentication
Code (MAC) was present in a received packet when ntpd was configured
to use symmetric cryptographic keys. A man-in-the-middle attacker
could use this flaw to send crafted packets that would be accepted by
a client or a peer without the attacker knowing the symmetric key.
(CVE-2015-1798)

The CVE-2015-1798 and CVE-2015-1799 issues were discovered by Miroslav
Lichvar of Red Hat.

Bug fixes :

* The ntpd daemon truncated symmetric keys specified in the key file
to 20 bytes. As a consequence, it was impossible to configure NTP
authentication to work with peers that use longer keys. The maximum
length of keys has now been changed to 32 bytes. (BZ#1053551)

* The ntp-keygen utility used the exponent of 3 when generating RSA
keys, and generating RSA keys failed when FIPS mode was enabled.
ntp-keygen has been modified to use the exponent of 65537, and
generating keys in FIPS mode now works as expected. (BZ#1184421)

* The ntpd daemon included a root delay when calculating its root
dispersion. Consequently, the NTP server reported larger root
dispersion than it should have and clients could reject the source
when its distance reached the maximum synchronization distance (1.5
seconds by default). Calculation of root dispersion has been fixed,
the root dispersion is now reported correctly, and clients no longer
reject the server due to a large synchronization distance.
(BZ#1045376)

* The ntpd daemon dropped incoming NTP packets if their source port
was lower than 123 (the NTP port). Clients behind Network Address
Translation (NAT) were unable to synchronize with the server if their
source port was translated to ports below 123. With this update, ntpd
no longer checks the source port number. (BZ#1171630)

Enhancements :

* This update introduces configurable access of memory segments used
for Shared Memory Driver (SHM) reference clocks. Previously, only the
first two memory segments were created with owner-only access,
allowing just two SHM reference clocks to be used securely on a
system. Now, the owner-only access to SHM is configurable with the
'mode' option, and it is therefore possible to use more SHM reference
clocks securely. (BZ#1122015)

* Support for nanosecond resolution has been added to the SHM
reference clock. Prior to this update, when a Precision Time Protocol
(PTP) hardware clock was used as a time source to synchronize the
system clock (for example, with the timemaster service from the
linuxptp package), the accuracy of the synchronization was limited due
to the microsecond resolution of the SHM protocol. The nanosecond
extension in the SHM protocol now enables sub-microsecond
synchronization of the system clock. (BZ#1117704)"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/002074.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6834dff9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"ntp-4.2.6p5-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-doc-4.2.6p5-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-perl-4.2.6p5-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntpdate-4.2.6p5-5.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
