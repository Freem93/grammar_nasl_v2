#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-404. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15241);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_cve_id("CVE-2003-0962");
  script_bugtraq_id(9153);
  script_osvdb_id(2898);
  script_xref(name:"DSA", value:"404");

  script_name(english:"Debian DSA-404-1 : rsync - heap overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The rsync team has received evidence that a vulnerability in all
versions of rsync prior to 2.5.7, a fast remote file copy program, was
recently used in combination with a Linux kernel vulnerability to
compromise the security of a public rsync server.

While this heap overflow vulnerability could not be used by itself to
obtain root access on an rsync server, it could be used in combination
with the recently announced do_brk() vulnerability in the Linux kernel
to produce a full remote compromise.

Please note that this vulnerability only affects the use of rsync as
an 'rsync server'. To see if you are running a rsync server you should
use the command 'netstat -a -n' to see if you are listening on TCP
port 873. If you are not listening on TCP port 873 then you are not
running an rsync server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://klecker.debian.org/~joey/rsync/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-404"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the rsync package immediately if you are providing remote sync
services. If you are running testing and provide remote sync services
please use the packages for woody.

For the stable distribution (woody) this problem has been fixed in
version 2.5.5-0.2.

However, since the Debian infrastructure is not yet fully functional
after the recent break-in, packages for the unstable distribution are
not able to enter the archive for a while. Hence they were placed in
Joey's home directory on the security machine."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rsync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/04");
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
if (deb_check(release:"3.0", prefix:"rsync", reference:"2.5.5-0.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
