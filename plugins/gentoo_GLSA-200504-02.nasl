#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200504-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(17676);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_osvdb_id(15125);
  script_xref(name:"GLSA", value:"200504-02");

  script_name(english:"GLSA-200504-02 : Sylpheed, Sylpheed-claws: Buffer overflow on message display");
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
"The remote host is affected by the vulnerability described in GLSA-200504-02
(Sylpheed, Sylpheed-claws: Buffer overflow on message display)

    Sylpheed and Sylpheed-claws fail to properly handle messages
    containing attachments with MIME-encoded filenames.
  
Impact :

    An attacker can send a malicious email message which, when
    displayed, would cause the program to crash, potentially allowing the
    execution of arbitrary code with the privileges of the user running the
    software.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://sylpheed.good-day.net/#changes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19b9ac9e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200504-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Sylpheed users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/sylpheed-1.0.4'
    All Sylpheed-claws users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/sylpheed-claws-1.0.4'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sylpheed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sylpheed-claws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-client/sylpheed", unaffected:make_list("ge 1.0.4"), vulnerable:make_list("lt 1.0.4"))) flag++;
if (qpkg_check(package:"mail-client/sylpheed-claws", unaffected:make_list("ge 1.0.4"), vulnerable:make_list("lt 1.0.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Sylpheed / Sylpheed-claws");
}
