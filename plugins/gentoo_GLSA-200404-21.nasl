#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-21.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14486);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_xref(name:"GLSA", value:"200404-21");

  script_name(english:"GLSA-200404-21 : Multiple Vulnerabilities in Samba");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200404-21
(Multiple Vulnerabilities in Samba)

    Two vulnerabilities have been discovered in Samba. The first vulnerability
    allows a local user who has access to the smbmount command to gain root. An
    attacker could place a setuid-root binary on a Samba share/server he or she
    controls, and then use the smbmount command to mount the share on the
    target UNIX box. The remote Samba server must support UNIX extensions for
    this to work. This has been fixed in version 3.0.2a.
    The second vulnerability is in the smbprint script. By creating a symlink
    from /tmp/smbprint.log, an attacker could cause the smbprint script to
    write to an arbitrary file on the system. This has been fixed in version
    3.0.2a-r2.
  
Impact :

    Local users with access to the smbmount command may gain root access. Also,
    arbitrary files may be overwritten using the smbprint script.
  
Workaround :

    To workaround the setuid bug, remove the setuid bits from the
    /usr/bin/smbmnt, /usr/bin/smbumount and /usr/bin/mount.cifs binaries.
    However, please note that this workaround will prevent ordinary users from
    mounting remote SMB and CIFS shares.
    To work around the smbprint vulnerability, set 'debug=no' in the smbprint
    configuration."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/353222/2004-04-09/2004-04-15/1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/lists/bugtraq/2004/Mar/0189.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should update to the latest version of the Samba package.
    The following commands will perform the upgrade:
    # emerge sync
    # emerge -pv '>=net-fs/samba-3.0.2a-r2'
    # emerge '>=net-fs/samba-3.0.2a-r2'
    Those who are using Samba's password database also need to run the
    following command:
    # pdbedit --force-initialized-passwords
    Those using LDAP for Samba passwords also need to check the sambaPwdLastSet
    attribute on each account, and ensure it is not 0."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"net-fs/samba", unaffected:make_list("ge 3.0.2a-r2"), vulnerable:make_list("le 3.0.2a"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-fs/samba");
}
