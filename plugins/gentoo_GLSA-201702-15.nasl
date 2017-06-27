#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201702-15.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(97258);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/21 14:37:43 $");

  script_cve_id("CVE-2015-8869");
  script_xref(name:"GLSA", value:"201702-15");

  script_name(english:"GLSA-201702-15 : OCaml: Buffer overflow and information disclosure");
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
"The remote host is affected by the vulnerability described in GLSA-201702-15
(OCaml: Buffer overflow and information disclosure)

    It was discovered that OCaml was vulnerable to a runtime bug that, on
      64-bit platforms, causes size arguments to internal memmove calls to be
      sign-extended from 32- to 64-bits before being passed to the memmove
      function. This leads to arguments between 2GiB and 4GiB being interpreted
      as larger than they are (specifically, a bit below 2^64), causing a
      buffer overflow. Further, arguments between 4GiB and 6GiB are interpreted
      as 4GiB smaller than they should be causing a possible information leak.
  
Impact :

    A remote attacker, able to interact with an OCaml-based application,
      could possibly obtain sensitive information or cause a Denial of Service
      condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201702-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OCaml users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/ocam-4.04.0'
    Packages which depend on OCaml may need to be recompiled. Tools such as
      qdepends (included in app-portage/portage-utils) may assist in
      identifying these packages:
      # emerge --oneshot --ask --verbose $(qdepends -CQ dev-lang/ocaml | sed
      's/^/=/')"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ocaml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-lang/ocaml", unaffected:make_list("ge 4.04.0"), vulnerable:make_list("lt 4.04.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OCaml");
}
