#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-065. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14902);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-1162");
  script_bugtraq_id(2927);
  script_osvdb_id(656);
  script_xref(name:"DSA", value:"065");

  script_name(english:"Debian DSA-065-1 : samba - remote file append/creation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Michal Zalewski discovered that Samba does not properly validate
 NetBIOS names from remote machines.

By itself that is not a problem, except if Samba is configured to
write log-files to a file that includes the NetBIOS name of the remote
side by using the `%m' macro in the `log file' command. In that case
an attacker could use a NetBIOS name like '../tmp/evil'. If the
log-file was set to '/var/log/samba/%s' Samba would then write to
/var/tmp/evil.

Since the NetBIOS name is limited to 15 characters and the `log file'
command could have an extension to the filename the results of this
are limited. However if the attacker is also able to create symbolic
links on the Samba server they could trick Samba into appending any
data they want to all files on the filesystem which Samba can write
to.

The Debian GNU/Linux packaged version of Samba has a safe
configuration and is not vulnerable.

As temporary workaround for systems that are vulnerable change all
occurrences of the `%m' macro in smb.conf to `%l' and restart Samba."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-065"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This has been fixed in version 2.0.7-3.4, and we recommend that you
upgrade your Samba package immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/06/23");
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
if (deb_check(release:"2.2", prefix:"samba", reference:"2.0.7-3.4")) flag++;
if (deb_check(release:"2.2", prefix:"samba-common", reference:"2.0.7-3.4")) flag++;
if (deb_check(release:"2.2", prefix:"samba-doc", reference:"2.0.7-3.4")) flag++;
if (deb_check(release:"2.2", prefix:"smbclient", reference:"2.0.7-3.4")) flag++;
if (deb_check(release:"2.2", prefix:"smbfs", reference:"2.0.7-3.4")) flag++;
if (deb_check(release:"2.2", prefix:"swat", reference:"2.0.7-3.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
