#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200803-25.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31612);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2008-1199", "CVE-2008-1218");
  script_bugtraq_id(28092, 28181);
  script_osvdb_id(42979, 43137);
  script_xref(name:"GLSA", value:"200803-25");

  script_name(english:"GLSA-200803-25 : Dovecot: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200803-25
(Dovecot: Multiple vulnerabilities)

    Dovecot uses the group configured via the 'mail_extra_groups' setting,
    which should be used to create lockfiles in the /var/mail directory,
    when accessing arbitrary files (CVE-2008-1199). Dovecot does not escape
    TAB characters in passwords when saving them, which might allow for
    argument injection in blocking passdbs such as MySQL, PAM or shadow
    (CVE-2008-1218).
  
Impact :

    Remote attackers can exploit the first vulnerability to disclose
    sensitive data, such as the mail of other users, or modify files or
    directories that are writable by group via a symlink attack. Please
    note that the 'mail_extra_groups' setting is set to the 'mail' group by
    default when the 'mbox' USE flag is enabled.
    The second vulnerability can be abused to inject arguments for internal
    fields. No exploitation vectors are known for this vulnerability that
    affect previously stable versions of Dovecot in Gentoo.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200803-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Dovecot users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/dovecot-1.0.13-r1'
    This version removes the 'mail_extra_groups' option and introduces a
    'mail_privileged_group' setting which is handled safely."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 59, 255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/19");
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

if (qpkg_check(package:"net-mail/dovecot", unaffected:make_list("ge 1.0.13-r1"), vulnerable:make_list("lt 1.0.13-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Dovecot");
}
