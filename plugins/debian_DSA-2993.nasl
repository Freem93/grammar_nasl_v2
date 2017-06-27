#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2993. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76949);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:48:47 $");

  script_cve_id("CVE-2014-5117");
  script_bugtraq_id(68968);
  script_xref(name:"DSA", value:"2993");

  script_name(english:"Debian DSA-2993-1 : tor - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered in Tor, a connection-based
low-latency anonymous communication system, resulting in information
leaks.

  - Relay-early cells could be used by colluding relays on
    the network to tag user circuits and so deploy traffic
    confirmation attacks [ CVE-2014-5117]. The updated
    version emits a warning and drops the circuit upon
    receiving inbound relay-early cells, preventing this
    specific kind of attack. Please consult the following
    advisory for more details about this issue :
    https://blog.torproject.org/blog/tor-security-advisory-r
    elay-early-traffic-confirmation-attack

  - A bug in the bounds-checking in the 32-bit
    curve25519-donna implementation could cause incorrect
    results on 32-bit implementations when certain malformed
    inputs were used along with a small class of private
    ntor keys. This flaw does not currently appear to allow
    an attacker to learn private keys or impersonate a Tor
    server, but it could provide a means to distinguish
    32-bit Tor implementations from 64-bit Tor
    implementations.
The following additional security-related improvements have been
implemented :

  - As a client, the new version will effectively stop using
    CREATE_FAST cells. While this adds computational load on
    the network, this approach can improve security on
    connections where Tor's circuit handshake is stronger
    than the available TLS connection security levels.
  - Prepare clients to use fewer entry guards by honoring
    the consensus parameters. The following article provides
    some background :

    https://blog.torproject.org/blog/improving-tors-anonymit
    y-changing-guard-parameters"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-5117"
  );
  # https://blog.torproject.org/blog/tor-security-advisory-relay-early-traffic-confirmation-attack
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df709f16"
  );
  # https://blog.torproject.org/blog/improving-tors-anonymity-changing-guard-parameters
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5cae368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2993"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tor packages.

For the stable distribution (wheezy), these problems have been fixed
in version 0.2.4.23-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"tor", reference:"0.2.4.23-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tor-dbg", reference:"0.2.4.23-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tor-geoipdb", reference:"0.2.4.23-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
