#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3701. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94260);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id("CVE-2016-1247");
  script_osvdb_id(146292);
  script_xref(name:"DSA", value:"3701");

  script_name(english:"Debian DSA-3701-1 : nginx - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dawid Golunski reported the nginx web server packages in Debian
suffered from a privilege escalation vulnerability (www-data to root)
due to the way log files are handled. This security update changes
ownership of the /var/log/nginx directory root. In addition,
/var/log/nginx has to be made accessible to local users, and local
users may be able to read the log files themselves local until the
next logrotate invocation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nginx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3701"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nginx packages.

For the stable distribution (jessie), this problem has been fixed in
version 1.6.2-5+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");
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
if (deb_check(release:"8.0", prefix:"nginx", reference:"1.6.2-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-common", reference:"1.6.2-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-doc", reference:"1.6.2-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-extras", reference:"1.6.2-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-extras-dbg", reference:"1.6.2-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-full", reference:"1.6.2-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-full-dbg", reference:"1.6.2-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-light", reference:"1.6.2-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"nginx-light-dbg", reference:"1.6.2-5+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
