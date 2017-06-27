#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1458. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29935);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:45:45 $");

  script_cve_id("CVE-2007-6599");
  script_bugtraq_id(27132);
  script_xref(name:"DSA", value:"1458");

  script_name(english:"Debian DSA-1458-1 : openafs - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A race condition in the OpenAFS fileserver allows remote attackers to
cause a denial of service (daemon crash) by simultaneously acquiring
and giving back file callbacks, which causes the handler for the
GiveUpAllCallBacks RPC to perform linked-list operations without the
host_glock lock."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1458"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages.

For the old stable distribution (sarge), this problem has been fixed
in version 1.3.81-3sarge3.

For the stable distribution (etch), this problem has been fixed in
version 1.4.2-6etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libopenafs-dev", reference:"1.3.81-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libpam-openafs-kaserver", reference:"1.3.81-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-client", reference:"1.3.81-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-dbserver", reference:"1.3.81-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-fileserver", reference:"1.3.81-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-kpasswd", reference:"1.3.81-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"openafs-modules-source", reference:"1.3.81-3sarge3")) flag++;
if (deb_check(release:"4.0", prefix:"libopenafs-dev", reference:"1.4.2-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpam-openafs-kaserver", reference:"1.4.2-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-client", reference:"1.4.2-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-dbg", reference:"1.4.2-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-dbserver", reference:"1.4.2-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-doc", reference:"1.4.2-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-fileserver", reference:"1.4.2-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-kpasswd", reference:"1.4.2-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-krb5", reference:"1.4.2-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-modules-source", reference:"1.4.2-6etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
