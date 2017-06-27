#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201612-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(95516);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/21 14:22:36 $");

  script_cve_id("CVE-2016-6313");
  script_xref(name:"GLSA", value:"201612-01");

  script_name(english:"GLSA-201612-01 : GnuPG: RNG output is predictable");
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
"The remote host is affected by the vulnerability described in GLSA-201612-01
(GnuPG: RNG output is predictable)

    A long standing bug (since 1998) in Libgcrypt (see &ldquo;GLSA 201610-04&rdquo;
      below) and GnuPG allows an attacker to predict the output from the
      standard RNG. Please review the &ldquo;Entropy Loss and Output Predictability
      in the Libgcrypt PRNG&rdquo; paper below for a deep technical analysis.
  
Impact :

    An attacker who obtains 580 bytes of the random number from the standard
      RNG can trivially predict the next 20 bytes of output.
    This flaw does not affect the default generation of keys, because
      running gpg for key creation creates at most 2 keys from the pool. For a
      single 4096 bit RSA key, 512 bytes of random are required and thus for
      the second key (encryption subkey), 20 bytes could be predicted from the
      the first key.
    However, the security of an OpenPGP key depends on the primary key
      (which was generated first) and thus the 20 predictable bytes should not
      be a problem.  For the default key length of 2048 bit nothing will be
      predictable.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://formal.iti.kit.edu/~klebanov/pubs/libgcrypt-cve-2016-6313.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.gentoo.org/glsa/201610-04"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201612-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GnuPG 1 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-crypt/gnupg-1.4.21'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/05");
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

if (qpkg_check(package:"app-crypt/gnupg", unaffected:make_list("ge 1.4.21"), vulnerable:make_list("lt 1.4.21"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GnuPG");
}
