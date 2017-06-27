#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201601-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(87985);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/10 14:14:54 $");

  script_cve_id("CVE-2016-0777", "CVE-2016-0778");
  script_xref(name:"GLSA", value:"201601-01");

  script_name(english:"GLSA-201601-01 : OpenSSH: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201601-01
(OpenSSH: Multiple vulnerabilities)

    Qualys have reported two issues in the &ldquo;roaming&rdquo; code included in
      the OpenSSH client, which provides undocumented, experimental support for
      resuming SSH connections. An OpenSSH client could be tricked into leaking
      parts of its memory to a malicious server. Furthermore, a buffer overflow
      can be exploited by a malicious server, but its exploitation requires
      non-default options and is mitigated due to another bug.
  
Impact :

    A remote attacker could entice a user to connect to a specially crafted
      OpenSSH server, possibly resulting in the disclosure of the user&rsquo;s
      private keys. Users with private keys that are not protected by a
      passphrase are advised to generate new keys if they have connected to an
      SSH server they don&rsquo;t fully trust.
    Note that no special configuration is required to be vulnerable as the
      roaming feature is enabled by default on the client.
  
Workaround :

    The issues can be worked around by disabling the roaming code. To do so,
      add &ldquo;UseRoaming no&rdquo; to the SSH client configuration, or specify &ldquo;-o
      &lsquo;UseRoaming no&rsquo;&rdquo; on the command line."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201601-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSH users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/openssh-7.1_p2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/openssh", unaffected:make_list("ge 7.1_p2"), vulnerable:make_list("lt 7.1_p2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenSSH");
}
