#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200401-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14442);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_xref(name:"GLSA", value:"200401-02");

  script_name(english:"GLSA-200401-02 : Honeyd remote detection vulnerability via a probe packet");
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
"The remote host is affected by the vulnerability described in GLSA-200401-02
(Honeyd remote detection vulnerability via a probe packet)

    A bug in handling NMAP fingerprints caused Honeyd to reply to TCP
    packets with both the SYN and RST flags set.  Watching for replies, it is
    possible to detect IP addresses simulated by Honeyd.
  
Impact :

    Although there are no public exploits known for Honeyd, the detection
    of Honeyd IP addresses may in some cases be undesirable.
  
Workaround :

    Honeyd 0.8 has been released along with an advisory to address this
    issue. In addition, Honeyd 0.8 drops privileges if permitted by the
    configuration file and contains command line flags to force dropping
    of privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.honeyd.org/adv.2004-01.asc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200401-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users are recommended to update to honeyd version 0.8:
    $> emerge sync
    $> emerge -pv '>=net-analyzer/honeyd-0.8'
    $> emerge '>=net-analyzer/honeyd-0.8'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:honeyd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/21");
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

if (qpkg_check(package:"net-analyzer/honeyd", unaffected:make_list("ge 0.8"), vulnerable:make_list("lt 0.8"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-analyzer/honeyd");
}
