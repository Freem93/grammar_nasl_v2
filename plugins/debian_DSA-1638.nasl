#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1638. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34223);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2006-5051", "CVE-2008-4109");
  script_bugtraq_id(20241);
  script_osvdb_id(29264);
  script_xref(name:"DSA", value:"1638");

  script_name(english:"Debian DSA-1638-1 : openssh - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It has been discovered that the signal handler implementing the login
timeout in Debian's version of the OpenSSH server uses functions which
are not async-signal-safe, leading to a denial of service
vulnerability (CVE-2008-4109 ).

The problem was originally corrected in OpenSSH 4.4p1 (CVE-2006-5051
), but the patch backported to the version released with etch was
incorrect.

Systems affected by this issue suffer from lots of zombie sshd
processes. Processes stuck with a '[net]' process title have also been
observed. Over time, a sufficient number of processes may accumulate
such that further login attempts are impossible. Presence of these
processes does not indicate active exploitation of this vulnerability.
It is possible to trigger this denial of service condition by
accident."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=498678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1638"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssh packages.

For the stable distribution (etch), this problem has been fixed in
version 4.3p2-9etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"openssh-client", reference:"4.3p2-9etch3")) flag++;
if (deb_check(release:"4.0", prefix:"openssh-server", reference:"4.3p2-9etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ssh", reference:"4.3p2-9etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ssh-askpass-gnome", reference:"4.3p2-9etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ssh-krb5", reference:"4.3p2-9etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
