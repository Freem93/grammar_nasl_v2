#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2971. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76349);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2014-3477", "CVE-2014-3532", "CVE-2014-3533");
  script_bugtraq_id(67986, 68337, 68339);
  script_osvdb_id(108033, 108619, 108620);
  script_xref(name:"DSA", value:"2971");

  script_name(english:"Debian DSA-2971-1 : dbus - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in dbus, an asynchronous
inter-process communication system. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2014-3477
    Alban Crequy at Collabora Ltd. discovered that
    dbus-daemon sends an AccessDenied error to the service
    instead of a client when the client is prohibited from
    accessing the service. A local attacker could use this
    flaw to cause a bus-activated service that is not
    currently running to attempt to start, and fail, denying
    other users access to this service.

  - CVE-2014-3532
    Alban Crequy at Collabora Ltd. discovered a bug in
    dbus-daemon's support for file descriptor passing. A
    malicious process could force system services or user
    applications to be disconnected from the D-Bus system by
    sending them a message containing a file descriptor,
    leading to a denial of service.

  - CVE-2014-3533
    Alban Crequy at Collabora Ltd. and Alejandro Martinez
    Suarez discovered that a malicious process could force
    services to be disconnected from the D-Bus system by
    causing dbus-daemon to attempt to forward invalid file
    descriptors to a victim process, leading to a denial of
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dbus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2971"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dbus packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.6.8-1+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"dbus", reference:"1.6.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-dbg", reference:"1.6.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-doc", reference:"1.6.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-x11", reference:"1.6.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-3", reference:"1.6.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-dev", reference:"1.6.8-1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
