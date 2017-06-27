#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200808-12.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(33891);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-2936", "CVE-2008-2937");
  script_osvdb_id(47658, 47659);
  script_xref(name:"GLSA", value:"200808-12");

  script_name(english:"GLSA-200808-12 : Postfix: Local privilege escalation vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200808-12
(Postfix: Local privilege escalation vulnerability)

    Sebastian Krahmer of SuSE has found that Postfix allows to deliver mail
    to root-owned symlinks in an insecure manner under certain conditions.
    Normally, Postfix does not deliver mail to symlinks, except to
    root-owned symlinks, for compatibility with the systems using symlinks
    in /dev like Solaris. Furthermore, some systems like Linux allow to
    hardlink a symlink, while the POSIX.1-2001 standard requires that the
    symlink is followed. Depending on the write permissions and the
    delivery agent being used, this can lead to an arbitrary local file
    overwriting vulnerability (CVE-2008-2936). Furthermore, the Postfix
    delivery agent does not properly verify the ownership of a mailbox
    before delivering mail (CVE-2008-2937).
  
Impact :

    The combination of these features allows a local attacker to hardlink a
    root-owned symlink such that the newly created symlink would be
    root-owned and would point to a regular file (or another symlink) that
    would be written by the Postfix built-in local(8) or virtual(8)
    delivery agents, regardless the ownership of the final destination
    regular file. Depending on the write permissions of the spool mail
    directory, the delivery style, and the existence of a root mailbox,
    this could allow a local attacker to append a mail to an arbitrary file
    like /etc/passwd in order to gain root privileges.
    The default configuration of Gentoo Linux does not permit any kind of
    user privilege escalation.
    The second vulnerability (CVE-2008-2937) allows a local attacker,
    already having write permissions to the mail spool directory which is
    not the case on Gentoo by default, to create a previously nonexistent
    mailbox before Postfix creates it, allowing to read the mail of another
    user on the system.
  
Workaround :

    The following conditions should be met in order to be vulnerable to
    local privilege escalation.
    The mail delivery style is mailbox, with the Postfix built-in
    local(8) or virtual(8) delivery agents.
    The mail spool directory (/var/spool/mail) is user-writeable.
    The user can create hardlinks pointing to root-owned symlinks
    located in other directories.
    Consequently, each one of the following workarounds is efficient.
    Verify that your /var/spool/mail directory is not writeable by a
    user. Normally on Gentoo, only the mail group has write access, and no
    end-user should be granted the mail group ownership.
    Prevent the local users from being able to create hardlinks
    pointing outside of the /var/spool/mail directory, e.g. with a
    dedicated partition.
    Use a non-builtin Postfix delivery agent, like procmail or
    maildrop.
    Use the maildir delivery style of Postfix ('home_mailbox=Maildir/'
    for example).
    Concerning the second vulnerability, check the write permissions of
    /var/spool/mail, or check that every Unix account already has a
    mailbox, by using Wietse Venema's Perl script available in the official
    advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://article.gmane.org/gmane.mail.postfix.announce/110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200808-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Postfix users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.5.3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postfix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-mta/postfix", unaffected:make_list("rge 2.4.7-r1", "ge 2.5.3-r1", "rge 2.4.8", "ge 2.4.9"), vulnerable:make_list("lt 2.5.3-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Postfix");
}
