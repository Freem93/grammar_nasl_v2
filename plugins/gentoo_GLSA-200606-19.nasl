#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200606-19.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21712);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/13 13:49:35 $");

  script_cve_id("CVE-2006-1173");
  script_xref(name:"GLSA", value:"200606-19");

  script_name(english:"GLSA-200606-19 : Sendmail: Denial of Service");
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
"The remote host is affected by the vulnerability described in GLSA-200606-19
(Sendmail: Denial of Service)

    Frank Sheiness discovered that the mime8to7() function can recurse
    endlessly during the decoding of multipart MIME messages until the
    stack of the process is filled and the process crashes.
  
Impact :

    By sending specially crafted multipart MIME messages, a remote
    attacker can cause a subprocess forked by Sendmail to crash. If
    Sendmail is not set to use a randomized queue processing, the attack
    will effectively halt the delivery of queued mails as well as the
    malformed one, incoming mail delivered interactively is not affected.
    Additionally, on systems where core dumps with an individual naming
    scheme (like 'core.pid') are enabled, a filesystem may fill up with
    core dumps. Core dumps are disabled by default in Gentoo.
  
Workaround :

    The Sendmail 8.13.7 release information offers some workarounds, please
    see the Reference below. Note that the issue has actually been fixed in
    the 8.13.6-r1 ebuild."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.sendmail.org/releases/8.13.7.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200606-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Sendmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/sendmail-8.13.6-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-mta/sendmail", unaffected:make_list("ge 8.13.6-r1"), vulnerable:make_list("lt 8.13.6-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Sendmail");
}
