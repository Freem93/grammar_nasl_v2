#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-192-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82715);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-1798", "CVE-2015-1799");
  script_bugtraq_id(73950, 73951);
  script_osvdb_id(120350, 120351);

  script_name(english:"Debian DLA-192-1 : ntp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Brief introduction 

CVE-2015-1798

When ntpd is configured to use a symmetric key to authenticate a
remote NTP server/peer, it checks if the NTP message authentication
code (MAC) in received packets is valid, but not if there actually is
any MAC included. Packets without a MAC are accepted as if they had a
valid MAC. This allows a MITM attacker to send false packets that are
accepted by the client/peer without having to know the symmetric key.
The attacker needs to know the transmit timestamp of the client to
match it in the forged reply and the false reply needs to reach the
client before the genuine reply from the server. The attacker doesn't
necessarily need to be relaying the packets between the client and the
server. Authentication using autokey doesn't have this problem as
there is a check that requires the key ID to be larger than
NTP_MAXKEY, which fails for packets without a MAC.

CVE-2015-1799

An attacker knowing that NTP hosts A and B are peering with each other
(symmetric association) can send a packet to host A with source
address of B which will set the NTP state variables on A to the values
sent by the attacker. Host A will then send on its next poll to B a
packet with originate timestamp that doesn't match the transmit
timestamp of B and the packet will be dropped. If the attacker does
this periodically for both hosts, they won't be able to synchronize to
each other. This is a known denial of service attack, described at
https://www.eecis.udel.edu/~mills/onwire.html . According to the
document the NTP authentication is supposed to protect symmetric
associations against this attack, but that doesn't seem to be the
case. The state variables are updated even when authentication fails
and the peers are sending packets with originate timestamps that don't
match the transmit timestamps on the receiving side.

ntp-keygen on big endian hosts

Using ntp-keygen to generate an MD5 key on big endian hosts resulted
in either an infite loop or an key of only 93 possible keys.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/04/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ntp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.eecis.udel.edu/~mills/onwire.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ntp, ntp-doc, and ntpdate packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");
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
if (deb_check(release:"6.0", prefix:"ntp", reference:"1:4.2.6.p2+dfsg-1+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"ntp-doc", reference:"1:4.2.6.p2+dfsg-1+deb6u3")) flag++;
if (deb_check(release:"6.0", prefix:"ntpdate", reference:"1:4.2.6.p2+dfsg-1+deb6u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
