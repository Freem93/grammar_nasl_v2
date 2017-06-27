#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201201-13.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(57655);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-3295", "CVE-2009-4212", "CVE-2010-0283", "CVE-2010-0629", "CVE-2010-1320", "CVE-2010-1321", "CVE-2010-1322", "CVE-2010-1323", "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021", "CVE-2010-4022", "CVE-2011-0281", "CVE-2011-0282", "CVE-2011-0283", "CVE-2011-0284", "CVE-2011-0285", "CVE-2011-1527", "CVE-2011-1528", "CVE-2011-1529", "CVE-2011-1530", "CVE-2011-4151");
  script_bugtraq_id(37486, 37749, 38260, 39247, 39599, 40235, 43756, 45116, 45117, 45118, 45122, 46265, 46269, 46271, 46272, 46881, 47310, 50273, 50929);
  script_osvdb_id(61423, 61795, 62391, 63569, 63975, 64744, 68525, 69607, 69608, 69609, 69610, 70083, 70907, 70908, 70909, 70910, 71183, 71789, 71972, 76659, 76660, 76661, 77572);
  script_xref(name:"GLSA", value:"201201-13");

  script_name(english:"GLSA-201201-13 : MIT Kerberos 5: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201201-13
(MIT Kerberos 5: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MIT Kerberos 5. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker may be able to execute arbitrary code with the
      privileges of the administration daemon or the Key Distribution Center
      (KDC) daemon, cause a Denial of Service condition, or possibly obtain
      sensitive information. Furthermore, a remote attacker may be able to
      spoof Kerberos authorization, modify KDC responses, forge user data
      messages, forge tokens, forge signatures, impersonate a client, modify
      user-visible prompt text, or have other unspecified impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201201-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MIT Kerberos 5 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-crypt/mit-krb5-1.9.2-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mit-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-crypt/mit-krb5", unaffected:make_list("ge 1.9.2-r1"), vulnerable:make_list("lt 1.9.2-r1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MIT Kerberos 5");
}
