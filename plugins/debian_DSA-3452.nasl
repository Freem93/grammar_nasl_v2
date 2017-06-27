#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3452. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88110);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-8614");
  script_osvdb_id(132164);
  script_xref(name:"DSA", value:"3452");

  script_name(english:"Debian DSA-3452-1 : claws-mail - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'DrWhax' of the Tails project reported that Claws Mail is missing
range checks in some text conversion functions. A remote attacker
could exploit this to run arbitrary code under the account of a user
that receives a message from them using Claws Mail."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/claws-mail"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/claws-mail"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3452"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the claws-mail packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 3.8.1-2+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 3.11.1-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:claws-mail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"claws-mail", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-bogofilter", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-dbg", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-doc", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-i18n", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-pgpinline", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-pgpmime", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-plugins", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-smime-plugin", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-spamassassin", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-tools", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"claws-mail-trayicon", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libclaws-mail-dev", reference:"3.8.1-2+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-acpi-notifier", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-address-keeper", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-archiver-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-attach-remover", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-attach-warner", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-bogofilter", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-bsfilter-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-clamd-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-dbg", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-doc", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-extra-plugins", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-fancy-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-feeds-reader", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-fetchinfo-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-gdata-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-i18n", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-libravatar", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-mailmbox-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-multi-notifier", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-newmail-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-pdf-viewer", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-perl-filter", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-pgpinline", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-pgpmime", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-plugins", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-python-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-smime-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-spam-report", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-spamassassin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-tnef-parser", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-tools", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"claws-mail-vcalendar-plugin", reference:"3.11.1-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libclaws-mail-dev", reference:"3.11.1-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
