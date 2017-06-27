#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-4077.
#

include("compat.inc");

if (description)
{
  script_id(58547);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 15:36:30 $");

  script_cve_id("CVE-2012-1104", "CVE-2012-1105");
  script_bugtraq_id(52279, 52280);
  script_xref(name:"FEDORA", value:"2012-4077");

  script_name(english:"Fedora 15 : php-pear-CAS-1.3.0-2.fc15 (2012-4077)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream changelog

Changes in version 1.3.0

Bug Fixes :

  - the saml logout url should be parsed urlencoded [#24]
    (dlineate)

    - fix a proxy mode bug introduced in a previous comitt
      [#16] (Adam Franco)

    - Fix include_path order so that the phpCAS path takes
      precedence [#13] (Adam Franco)

    - fix invalid characters in the php session naming [#17]
      (Joachim Fritschi)

    - fix an initialisation problem introduced in the PGT
      storage [18] (Daniel Frett)

    - make sure the PGTStorage object is initialized if a
      user is utilizing the createTable method [#4] (Daniel
      Frett)

    - Fix error message in
      phpCAS::setCacheTimesForAuthRecheck() [PHPCAS-132/#1]
      (Bradley Froehle)

    - Always return attributes in utf8 [PHPCAS-102]

    - Fix warning during debugging if debug is set to false
      [PHPCAS-123] (Sean Watkins)

New Features :

  - Add a script to create the PGT db table in proxy mode
    [#11] (Joachim Fritschi)

    - Switch to the Apache License [#5] (Adam Franco,
      Joachim Fritschi)

    - Move to github and add all necessary file to package
      [#12] (Adam Franco)

    - New build process for github [#12] (Adam Franco)

    - Update unit tests to work with the lastest phpunit
      version [PHPCAS-128] (Adam Franco)

    - Refacatoring of the protocol decision making to allow
      validation of proxied usage [PHPCAS-69] (Joachim
      Fritschi, Adam Franco)

    - Rebroadcast of logout and pgtiou to support clustered
      phpcas [PHPCAS-100] (Matthew Selwood, Adam Franco)

Improvements :

  - Improved cookie handling [] (Adam Franco

    - Indent, format and user name guidelines of PEAR [#14]
      (Joachim Fritschi)

    - Add a class autoloading feature [PHPCAS-125/#8]
      (Joachim Fritschi)

    - Remove global variables [PHPCAS-126] (Adam Franco)

    - Implementation of an exception framework to allow
      gracefull termination [PHPCAS-109] (Joachim Fritschi)

    - enable single sign-out when session has already
      started [#29] (Benvii) Security Fixes :

  - CVE-2012-1104 validate proxied usage of a service
    [PHPCAS-69] (Joachim Fritschi, Adam Franco)

    - CVE-2012-1105 change the default PGT save path to the
      session storage path and set proper permissions [#22]
      (Joachim Fritschi)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=801343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=801347"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-March/076641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46171f92"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pear-CAS package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear-CAS");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"php-pear-CAS-1.3.0-2.fc15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pear-CAS");
}
