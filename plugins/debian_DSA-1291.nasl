#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1291. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25228);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/03/19 14:28:18 $");

  script_cve_id("CVE-2007-2444", "CVE-2007-2446", "CVE-2007-2447");
  script_bugtraq_id(23972, 23973, 23974);
  script_xref(name:"DSA", value:"1291");

  script_name(english:"Debian DSA-1291-1 : samba - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been identified in Samba, the SMB/CIFS file- and
print-server implementation for GNU/Linux.

  - CVE-2007-2444
    When translating SIDs to/from names using Samba local
    list of user and group accounts, a logic error in the
    smbd daemon's internal security stack may result in a
    transition to the root user id rather than the non-root
    user. The user is then able to temporarily issue
    SMB/CIFS protocol operations as the root user. This
    window of opportunity may allow the attacker to
    establish addition means of gaining root access to the
    server.

  - CVE-2007-2446
    Various bugs in Samba's NDR parsing can allow a user to
    send specially crafted MS-RPC requests that will
    overwrite the heap space with user defined data.

  - CVE-2007-2447
    Unescaped user input parameters are passed as arguments
    to /bin/sh allowing for remote command execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1291"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba package.

For the stable distribution (etch), these problems have been fixed in
version 3.0.24-6etch1.

For the testing and unstable distributions (lenny and sid,
respectively), these problems have been fixed in version 3.0.25-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libpam-smbpass", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsmbclient", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsmbclient-dev", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-samba", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"samba", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"samba-common", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"samba-dbg", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"samba-doc", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"samba-doc-pdf", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"smbclient", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"smbfs", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"swat", reference:"3.0.24-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"winbind", reference:"3.0.24-6etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
