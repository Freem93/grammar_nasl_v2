#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-193-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82716);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_bugtraq_id(73948, 73955, 73956);
  script_osvdb_id(120393, 120394, 120395);

  script_name(english:"Debian DLA-193-1 : chrony security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2015-1853 :

Protect authenticated symmetric NTP associations against DoS attacks.

An attacker knowing that NTP hosts A and B are peering with
each other (symmetric association) can send a packet with
random timestamps to host A with source address of B which
will set the NTP state variables on A to the values sent by
the attacker. Host A will then send on its next poll to B a
packet with originate timestamp that doesn't match the
transmit timestamp of B and the packet will be dropped. If
the attacker does this periodically for both hosts, they
won't be able to synchronize to each other. It is a
denial of service attack.

According to [1], NTP authentication is supposed to protect
symmetric associations against this attack, but in the NTPv3
(RFC 1305) and NTPv4 (RFC 5905) specifications the state
variables are updated before the authentication check is
performed, which means the association is vulnerable to the
attack even when authentication is enabled.

To fix this problem, save the originate and local timestamps
only when the authentication check (test5) passed.

[1] https://www.eecis.udel.edu/~mills/onwire.html

CVE-2015-1821 :

Fix access configuration with subnet size indivisible by 4.

When NTP or cmdmon access was configured (from chrony.conf
or via authenticated cmdmon) with a subnet size that is
indivisible by 4 and an address that has nonzero bits in the
4-bit subnet remainder (e.g. 192.168.15.0/22 or f000::/3),
the new setting was written to an incorrect location,
possibly outside the allocated array.

An attacker that has the command key and is allowed to
access cmdmon (only localhost is allowed by default) could
exploit this to crash chronyd or possibly execute arbitrary
code with the privileges of the chronyd process.

CVE-2015-1822 :

Fix initialization of reply slots for authenticated commands.

When allocating memory to save unacknowledged replies to
authenticated command requests, the last 'next' pointer was
not initialized to NULL. When all allocated reply slots were
used, the next reply could be written to an invalid memory
instead of allocating a new slot for it.

An attacker that has the command key and is allowed to
access cmdmon (only localhost is allowed by default) could
exploit this to crash chronyd or possibly execute arbitrary
code with the privileges of the chronyd process.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/04/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/chrony"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.eecis.udel.edu/~mills/onwire.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected chrony package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chrony");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/12");
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
if (deb_check(release:"6.0", prefix:"chrony", reference:"1.24-3+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
