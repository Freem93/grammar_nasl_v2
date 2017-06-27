#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1516. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31587);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2008-1199", "CVE-2008-1218");
  script_xref(name:"DSA", value:"1516");

  script_name(english:"Debian DSA-1516-1 : dovecot - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Prior to this update, the default configuration for Dovecot used by
Debian runs the server daemons with group mail privileges. This means
that users with write access to their mail directory on the server
(for example, through an SSH login) could read and also delete via a
symbolic link mailboxes owned by other users for which they do not
have direct access (CVE-2008-1199 ). In addition, an internal
interpretation conflict in password handling has been addressed
proactively, even though it is not known to be exploitable
(CVE-2008-1218 ).

Note that applying this update requires manual action: The
configuration setting 'mail_extra_groups = mail' has been replaced
with 'mail_privileged_group = mail'. The update will show a
configuration file conflict in /etc/dovecot/dovecot.conf. It is
recommended that you keep the currently installed configuration file,
and change the affected line. For your reference, the sample
configuration (without your local changes) will have been written to
/etc/dovecot/dovecot.conf.dpkg-new.

If your current configuration uses mail_extra_groups with a value
different from 'mail', you may have to resort to themail_access_groups
configuration directive."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=469457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1516"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the old stable distribution (sarge), no updates are provided. We
recommend that you consider upgrading to the stable distribution.

For the stable distribution (etch), these problems have been fixed in
version 1.0.rc15-2etch4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(16, 59, 255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"dovecot-common", reference:"1.0.rc15-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"dovecot-imapd", reference:"1.0.rc15-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"dovecot-pop3d", reference:"1.0.rc15-2etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
