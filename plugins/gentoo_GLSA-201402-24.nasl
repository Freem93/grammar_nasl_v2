#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201402-24.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(72638);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/25 13:26:59 $");

  script_cve_id("CVE-2012-6085", "CVE-2013-4242", "CVE-2013-4351", "CVE-2013-4402");
  script_bugtraq_id(57102, 61464, 62857, 62921);
  script_osvdb_id(88865, 88866, 95657, 97339, 98164);
  script_xref(name:"GLSA", value:"201402-24");

  script_name(english:"GLSA-201402-24 : GnuPG, Libgcrypt: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201402-24
(GnuPG, Libgcrypt: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in GnuPG and Libgcrypt.
      Please review the CVE identifiers referenced below for details.
  
Impact :

    An unauthenticated remote attacker may be able to execute arbitrary code
      with the privileges of the user running GnuPG, cause a Denial of Service
      condition, or bypass security restrictions. Additionally, a side-channel
      attack may allow a local attacker to recover a private key, please review
      &ldquo;Flush+Reload: a High Resolution, Low Noise, L3 Cache Side-Channel
      Attack&rdquo; in the References section for further details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://eprint.iacr.org/2013/448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201402-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GnuPG 2.0 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-crypt/gnupg-2.0.22'
    All GnuPG 1.4 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-crypt/gnupg-1.4.16'
    All Libgcrypt users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/libgcrypt-1.5.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libgcrypt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/libgcrypt", unaffected:make_list("ge 1.5.3"), vulnerable:make_list("lt 1.5.3"))) flag++;
if (qpkg_check(package:"app-crypt/gnupg", unaffected:make_list("ge 2.0.22", "rge 1.4.16", "rge 1.4.17", "rge 1.4.18", "rge 1.4.19", "rge 1.4.20", "rge 1.4.21"), vulnerable:make_list("lt 2.0.22"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GnuPG / Libgcrypt");
}
