#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2452. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58754);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-0216");
  script_bugtraq_id(73851);
  script_osvdb_id(81511);
  script_xref(name:"DSA", value:"2452");

  script_name(english:"Debian DSA-2452-1 : apache2 - insecure default configuration");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Niels Heinen noticed a security issue with the default Apache
configuration on Debian if certain scripting modules like mod_php or
mod_rivet are installed. The problem arises because the directory
/usr/share/doc, which is mapped to the URL /doc, may contain example
scripts that can be executed by requests to this URL. Although access
to the URL /doc is restricted to connections from localhost, this
still creates security issues in two specific configurations :

  - if some front-end server on the same host forwards
    connections to an apache2 backend server on the
    localhost address, or
  - if the machine running apache2 is also used for web
    browsing.

Systems not meeting one of these two conditions are not known to be
vulnerable. The actual security impact depends on which packages (and
accordingly which example scripts) are installed on the system.
Possible issues include cross site scripting, code execution, or
leakage of sensitive data.


This updates removes the problematic configuration sections from the
files /etc/apache2/sites-available/default and .../default-ssl. When
upgrading, you should not blindly allow dpkg to replace those files,
though. Rather you should merge the changes, namely the removal of
the'Alias /doc '/usr/share/doc'' line and the related '<Directory
'/usr/share/doc/'>' block, into your versions of these config files.
You may also want to check if you have copied these sections to any
additional virtual host configurations."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2452"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages and adjust the configuration.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2.16-6+squeeze7."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"apache2", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-dbg", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-doc", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-event", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-itk", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-prefork", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-worker", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-prefork-dev", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec-custom", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-threaded-dev", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-utils", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-bin", reference:"2.2.16-6+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-common", reference:"2.2.16-6+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
