#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-956. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22822);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/18 00:19:44 $");

  script_cve_id("CVE-2006-0353");
  script_osvdb_id(22695);
  script_xref(name:"DSA", value:"956");

  script_name(english:"Debian DSA-956-1 : lsh-server - filedescriptor leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stefan Pfetzing discovered that lshd, a Secure Shell v2 (SSH2)
protocol server, leaks a couple of file descriptors, related to the
randomness generator, to user shells which are started by lshd. A
local attacker can truncate the server's seed file, which may prevent
the server from starting, and with some more effort, maybe also crack
session keys.

After applying this update, you should remove the server's seed file
(/var/spool/lsh/yarrow-seed-file) and then regenerate it with
'lsh-make-seed --server' as root.

For security reasons, lsh-make-seed really needs to be run from the
console of the system you are running it on. If you run lsh-make-seed
using a remote shell, the timing information lsh-make-seed uses for
its random seed creation is likely to be screwed. If need be, you can
generate the random seed on a different system than that which it will
eventually be on, by installing the lsh-utils package and running
'lsh-make-seed -o my-other-server-seed-file'. You may then transfer
the seed to the destination system as using a secure connection.

The old stable distribution (woody) may not be affected by this
problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=349303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-956"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lsh-server package.

For the stable distribution (sarge) this problem has been fixed in
version 2.0.1-3sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lsh-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"lsh-client", reference:"2.0.1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"lsh-server", reference:"2.0.1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"lsh-utils", reference:"2.0.1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"lsh-utils-doc", reference:"2.0.1-3sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
