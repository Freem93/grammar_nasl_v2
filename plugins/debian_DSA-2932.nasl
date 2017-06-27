#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2932. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74095);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-4344", "CVE-2014-2894");
  script_bugtraq_id(62773, 66932);
  script_osvdb_id(106531);
  script_xref(name:"DSA", value:"2932");

  script_name(english:"Debian DSA-2932-1 : qemu - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in qemu, a fast processor
emulator.

  - CVE-2013-4344
    Buffer overflow in the SCSI implementation in QEMU, when
    a SCSI controller has more than 256 attached devices,
    allows local users to gain privileges via a small
    transfer buffer in a REPORT LUNS command.

  - CVE-2014-2894
    Off-by-one error in the cmd_smart function in the smart
    self test in hw/ide/core.c in QEMU allows local users to
    have unspecified impact via a SMART EXECUTE OFFLINE
    command that triggers a buffer underflow and memory
    corruption."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=745157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=725944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2932"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qemu packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.1.2+dfsg-6a+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/20");
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
if (deb_check(release:"7.0", prefix:"qemu", reference:"1.1.2+dfsg-6a+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-keymaps", reference:"1.1.2+dfsg-6a+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-system", reference:"1.1.2+dfsg-6a+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-user", reference:"1.1.2+dfsg-6a+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-user-static", reference:"1.1.2+dfsg-6a+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-utils", reference:"1.1.2+dfsg-6a+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
