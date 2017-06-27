#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-335-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(86640);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/06/13 13:30:09 $");

  script_cve_id("CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7855", "CVE-2015-7871");
  script_bugtraq_id(75589);
  script_osvdb_id(116071, 123974, 126663, 126664, 126665, 126666, 129298, 129299, 129302, 129303, 129304, 129307, 129308, 129309, 129311, 129315);
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"Debian DLA-335-1 : ntp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues where found in ntp :

CVE-2015-5146

A flaw was found in the way ntpd processed certain remote
configuration packets. An attacker could use a specially crafted
package to cause ntpd to crash if :

  - ntpd enabled remote configuration

  - The attacker had the knowledge of the configuration
    password

  - The attacker had access to a computer entrusted to
    perform remote configuration

    Note that remote configuration is disabled by default in
    NTP. 

CVE-2015-5194

It was found that ntpd could crash due to an uninitialized variable
when processing malformed logconfig configuration commands.

CVE-2015-5195

It was found that ntpd exits with a segmentation fault when a
statistics type that was not enabled during compilation (e.g.
timingstats) is referenced by the statistics or filegen configuration
command

CVE-2015-5219

It was discovered that sntp program would hang in an infinite loop
when a crafted NTP packet was received, related to the conversion of
the precision value in the packet to double.

CVE-2015-5300

It was found that ntpd did not correctly implement the -g option:
Normally, ntpd exits with a message to the system log if the offset
exceeds the panic threshold, which is 1000 s by default. This option
allows the time to be set to any value without restriction; however,
this can happen only once. If the threshold is exceeded after that,
ntpd will exit with a message to the system log. This option can be
used with the -q and -x options. ntpd could actually step the clock
multiple times by more than the panic threshold if its clock
discipline doesn't have enough time to reach the sync state and stay
there for at least one update. If a man-in-the-middle attacker can
control the NTP traffic since ntpd was started (or maybe up to 15-30
minutes after that), they can prevent the client from reaching the
sync state and force it to step its clock by any amount any number of
times, which can be used by attackers to expire certificates, etc.
This is contrary to what the documentation says. Normally, the
assumption is that an MITM attacker can step the clock more than the
panic threshold only once when ntpd starts and to make a larger
adjustment the attacker has to divide it into multiple smaller steps,
each taking 15 minutes, which is slow.

CVE-2015-7691, CVE-2015-7692, CVE-2015-7702

It was found that the fix for CVE-2014-9750 was incomplete: three
issues were found in the value length checks in ntp_crypto.c, where a
packet with particular autokey operations that contained malicious
data was not always being completely validated. Receipt of these
packets can cause ntpd to crash.

CVE-2015-7701

A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd is
configured to use autokey authentication, an attacker could send
packets to ntpd that would, after several days of ongoing attack,
cause it to run out of memory.

CVE-2015-7703

Miroslav Lichv&aacute;r of Red Hat found that the :config command can
be used to set the pidfile and driftfile paths without any
restrictions. A remote attacker could use this flaw to overwrite a
file on the file system with a file containing the pid of the ntpd
process (immediately) or the current estimated drift of the system
clock (in hourly intervals). For example: ntpq -c ':config pidfile
/tmp/ntp.pid' ntpq -c ':config driftfile /tmp/ntp.drift' In Debian
ntpd is configured to drop root privileges, which limits the impact of
this issue.

CVE-2015-7704

When ntpd as an NTP client receives a Kiss-of-Death (KoD) packet from
the server to reduce its polling rate, it doesn't check if the
originate timestamp in the reply matches the transmit timestamp from
its request. An off-path attacker can send a crafted KoD packet to the
client, which will increase the client's polling interval to a large
value and effectively disable synchronization with the server.

CVE-2015-7850

An exploitable denial of service vulnerability exists in the remote
configuration functionality of the Network Time Protocol. A specially
crafted configuration file could cause an endless loop resulting in a
denial of service. An attacker could provide a the malicious
configuration file to trigger this vulnerability.

CVE-2015-7851

A potential path traversal vulnerability exists in the config file
saving of ntpd on VMS. A specially crafted path could cause a path
traversal potentially resulting in files being overwritten. An
attacker could provide a malicious path to trigger this vulnerability.

This issue does not affect Debian.

CVE-2015-7852

A potential off by one vulnerability exists in the cookedprint
functionality of ntpq. A specially crafted buffer could cause a buffer
overflow potentially resulting in null byte being written out of
bounds.

CVE-2015-7855

It was found that NTP's decodenetnum() would abort with an assertion
failure when processing a mode 6 or mode 7 packet containing an
unusually long data value where a network address was expected. This
could allow an authenticated attacker to crash ntpd.

CVE-2015-7871

An error handling logic error exists within ntpd that manifests due to
improper error condition handling associated with certain crypto-NAK
packets. An unauthenticated, off&shy;-path attacker can force ntpd
processes on targeted servers to peer with time sources of the
attacker's choosing by transmitting symmetric active crypto&shy;-NAK
packets to ntpd. This attack bypasses the authentication typically
required to establish a peer association and allows an attacker to
make arbitrary changes to system time.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/10/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ntp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ntp, ntp-doc, and ntpdate packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"ntp", reference:"1:4.2.6.p2+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"ntp-doc", reference:"1:4.2.6.p2+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"ntpdate", reference:"1:4.2.6.p2+dfsg-1+deb6u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
