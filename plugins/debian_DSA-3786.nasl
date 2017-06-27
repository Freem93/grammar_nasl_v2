#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3786. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97135);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/02/27 15:13:33 $");

  script_cve_id("CVE-2017-5953");
  script_osvdb_id(151922);
  script_xref(name:"DSA", value:"3786");

  script_name(english:"Debian DSA-3786-1 : vim - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Editor spell files passed to the vim (Vi IMproved) editor may result
in an integer overflow in memory allocation and a resulting buffer
overflow which potentially could result in the execution of arbitrary
code or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=854969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/vim"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3786"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vim packages.

For the stable distribution (jessie), this problem has been fixed in
version 2:7.4.488-7+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"vim", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-athena", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-common", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-dbg", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-doc", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-gnome", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-gtk", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-gui-common", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-lesstif", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-nox", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-runtime", reference:"2:7.4.488-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"vim-tiny", reference:"2:7.4.488-7+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
