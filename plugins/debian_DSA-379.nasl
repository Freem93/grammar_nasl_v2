#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-379. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15216);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:11:34 $");

  script_cve_id("CVE-2003-0773", "CVE-2003-0774", "CVE-2003-0775", "CVE-2003-0776", "CVE-2003-0777", "CVE-2003-0778");
  script_bugtraq_id(8593, 8594, 8595, 8596, 8597, 8600);
  script_xref(name:"DSA", value:"379");

  script_name(english:"Debian DSA-379-1 : sane-backends - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Alexander Hvostov, Julien Blache and Aurelien Jarno discovered several
security-related problems in the sane-backends package, which contains
an API library for scanners including a scanning daemon (in the
package libsane) that can be remotely exploited. These problems allow
a remote attacker to cause a segmentation fault and/or consume
arbitrary amounts of memory. The attack is successful, even if the
attacker's computer isn't listed in saned.conf.

You are only vulnerable if you actually run saned e.g. in xinetd or
inetd. If the entries in the configuration file of xinetd or inetd
respectively are commented out or do not exist, you are safe.

Try 'telnet localhost 6566' on the server that may run saned. If you
get 'connection refused' saned is not running and you are safe.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CAN-2003-0773 :
    saned checks the identity (IP address) of the remote
    host only after the first communication took place
    (SANE_NET_INIT). So everyone can send that RPC, even if
    the remote host is not allowed to scan (not listed in
    saned.conf).

  - CAN-2003-0774 :

    saned lacks error checking nearly everywhere in the
    code. So connection drops are detected very late. If the
    drop of the connection isn't detected, the access to the
    internal wire buffer leaves the limits of the allocated
    memory. So random memory 'after' the wire buffer is read
    which will be followed by a segmentation fault.

  - CAN-2003-0775 :

    If saned expects strings, it mallocs the memory
    necessary to store the complete string after it receives
    the size of the string. If the connection was dropped
    before transmitting the size, malloc will reserve an
    arbitrary size of memory. Depending on that size and the
    amount of memory available either malloc fails (->saned
    quits nicely) or a huge amount of memory is allocated.
    Swapping and OOM measures may occur depending on the
    kernel.

  - CAN-2003-0776 :

    saned doesn't check the validity of the RPC numbers it
    gets before getting the parameters.

  - CAN-2003-0777 :

    If debug messages are enabled and a connection is
    dropped, non-null-terminated strings may be printed and
    segmentation faults may occur.

  - CAN-2003-0778 :

    It's possible to allocate an arbitrary amount of memory
    on the server running saned even if the connection isn't
    dropped. At the moment this cannot easily be fixed
    according to the author. Better limit the total amount
    of memory saned may use (ulimit)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-379"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libsane packages.

For the stable distribution (woody) this problem has been fixed in
version 1.0.7-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sane-backends");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libsane", reference:"1.0.7-4")) flag++;
if (deb_check(release:"3.0", prefix:"libsane-dev", reference:"1.0.7-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
