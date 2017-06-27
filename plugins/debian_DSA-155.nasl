#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-155. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14992);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/17 23:45:46 $");

  script_cve_id("CVE-2002-0970");
  script_bugtraq_id(5410);
  script_osvdb_id(59566);
  script_xref(name:"DSA", value:"155");

  script_name(english:"Debian DSA-155-1 : kdelibs - privacy escalation with Konqueror");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Due to a security engineering oversight, the SSL library from KDE,
which Konqueror uses, doesn't check whether an intermediate
certificate for a connection is signed by the certificate authority as
safe for the purpose, but accepts it when it is signed. This makes it
possible for anyone with a valid VeriSign SSL site certificate to
forge any other VeriSign SSL site certificate, and abuse Konqueror
users.

A local root exploit using artsd has been discovered which exploited
an insecure use of a format string. The exploit wasn't working on a
Debian system since artsd wasn't running setuid root. Neither artsd
nor artswrapper need to be setuid root anymore since current computer
systems are fast enough to handle the audio data in time.

These problems have been fixed in version 2.2.2-13.woody.2 for the
current stable distribution (woody). The old stable distribution
(potato) is not affected, since it doesn't contain KDE packages. The
unstable distribution (sid) is not yet fixed, but new packages are
expected in the future, the fixed version will be version 2.2.2-14 or
higher."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-155"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the kdelibs and libarts packages and restart Konqueror."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/17");
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
if (deb_check(release:"3.0", prefix:"kdelibs-dev", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3-bin", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3-cups", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3-doc", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"libarts", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"libarts-alsa", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"libarts-dev", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"libkmid", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"libkmid-alsa", reference:"2.2.2-13.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"libkmid-dev", reference:"2.2.2-13.woody.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
