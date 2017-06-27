#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200905-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(38920);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:12:00 $");

  script_cve_id("CVE-2009-0159", "CVE-2009-1252");
  script_bugtraq_id(34481, 35017);
  script_osvdb_id(53593, 54576);
  script_xref(name:"GLSA", value:"200905-08");

  script_name(english:"GLSA-200905-08 : NTP: Remote execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200905-08
(NTP: Remote execution of arbitrary code)

    Multiple vulnerabilities have been found in the programs included in
    the NTP package:
    Apple Product Security reported a
    boundary error in the cookedprint() function in ntpq/ntpq.c, possibly
    leading to a stack-based buffer overflow (CVE-2009-0159).
    Chris Ries of CMU reported a boundary error within the
    crypto_recv() function in ntpd/ntp_crypto.c, possibly leading to a
    stack-based buffer overflow (CVE-2009-1252).
  
Impact :

    A remote attacker might send a specially crafted package to a machine
    running ntpd, possibly resulting in the remote execution of arbitrary
    code with the privileges of the user running the daemon, or a Denial of
    Service. NOTE: Successful exploitation requires the 'autokey' feature
    to be enabled. This feature is only available if NTP was built with the
    'ssl' USE flag.
    Furthermore, a remote attacker could entice a user into connecting to a
    malicious server using ntpq, possibly resulting in the remote execution
    of arbitrary code with the privileges of the user running the
    application, or a Denial of Service.
  
Workaround :

    You can protect against CVE-2009-1252 by disabling the 'ssl' USE flag
    and recompiling NTP."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200905-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All NTP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/ntp-4.2.4_p7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/ntp", unaffected:make_list("ge 4.2.4_p7"), vulnerable:make_list("lt 4.2.4_p7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NTP");
}
