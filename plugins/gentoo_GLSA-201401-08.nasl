#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201401-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(72016);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/14 13:50:03 $");

  script_cve_id("CVE-2013-5211");
  script_osvdb_id(101576);
  script_xref(name:"CERT", value:"348126");
  script_xref(name:"GLSA", value:"201401-08");

  script_name(english:"GLSA-201401-08 : NTP: Traffic amplification");
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
"The remote host is affected by the vulnerability described in GLSA-201401-08
(NTP: Traffic amplification)

    ntpd is susceptible to a reflected Denial of Service attack. Please
      review the CVE identifiers and references below for details.
  
Impact :

    An unauthenticated remote attacker may conduct a distributed reflective
      Denial of Service attack on another user via a vulnerable NTP server.
  
Workaround :

    We modified the default ntp configuration in =net-misc/ntp-4.2.6_p5-r10
      and added &ldquo;noquery&rdquo; to the default restriction which disallows anyone
      to query the ntpd status, including &ldquo;monlist&rdquo;.
    If you use a non-default configuration, and provide a ntp service to
      untrusted networks, we highly recommend you to revise your configuration
      to disable mode 6 and 7 queries for any untrusted (public) network.
    You can always enable these queries for specific trusted networks. For
      more details please see the &ldquo;Access Control Support&rdquo; chapter in the
      ntp.conf(5) man page."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201401-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All NTP users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/ntp-4.2.6_p5-r10'
    Note that the updated package contains a modified default configuration
      only. You may need to modify your configuration further."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/ntp", unaffected:make_list("ge 4.2.6_p5-r10"), vulnerable:make_list("lt 4.2.6_p5-r10"))) flag++;

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
