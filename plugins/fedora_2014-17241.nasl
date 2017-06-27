#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-17241.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80291);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/19 22:23:31 $");

  script_cve_id("CVE-2014-8142");
  script_bugtraq_id(71791);
  script_xref(name:"FEDORA", value:"2014-17241");

  script_name(english:"Fedora 21 : php-5.6.4-2.fc21 (2014-17241)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"18 Dec 2014, PHP 5.6.4\\r\\n\\r\\nCore:\\r\\n* Fixed bug #68091 (Some
Zend headers lack appropriate extern 'C' blocks). (Adam)\\r\\n* Fixed
bug #68104 (Segfault while pre-evaluating a disabled function).
(Laruence)\\r\\n* Fixed bug #68185 ('Inconsistent insteadof
definition.'- incorrectly triggered). (Julien)\\r\\n* Fixed bug #68355
(Inconsistency in example php.ini comments). (Chris McCafferty)\\r\\n*
Fixed bug #68370 ('unset($this)' can make the program crash).
(Laruence)\\r\\n* Fixed bug #68422 (Incorrect argument reflection info
for array_multisort()). (Alexander Lisachenko)\\r\\n* Fixed bug #68446
(Array constant not accepted for array parameter default). (Bob,
Dmitry)\\r\\n* Fixed bug #68545 (NULL pointer dereference in
unserialize.c). (Anatol)\\r\\n* Fixed bug #68594 (Use after free
vulnerability in unserialize()). (CVE-2014-8142) (Stefan
Esser)\\r\\n\\r\\nDate:\\r\\n* Fixed day_of_week function as it could
sometimes return negative values internally.
(Derick)\\r\\n\\r\\nFPM:\\r\\n* Fixed bug #68381 (fpm_unix_init_main
ignores log_level). (David Zuelke, Remi)\\r\\n* Fixed bug #68420
(listen=9000 listens to ipv6 localhost instead of all addresses).
(Remi)\\r\\n* Fixed bug #68421 (access.format='%R' doesn't log ipv6
address). (Remi)\\r\\n* Fixed bug #68423 (PHP-FPM will no longer load
all pools). (Remi)\\r\\n* Fixed bug #68428 (listen.allowed_clients is
IPv4 only). (Remi)\\r\\n* Fixed bug #68452 (php-fpm man page is
oudated). (Remi)\\r\\n* Fixed request #68458 (Change pm.start_servers
default warning to notice). (David Zuelke, Remi)\\r\\n* Fixed bug
#68463 (listen.allowed_clients can silently result in no allowed
access). (Remi)\\r\\n* Fixed request #68391 (php-fpm conf files
loading order). (Florian Margaine, Remi)\\r\\n* Fixed bug #68478
(access.log don't use prefix). (Remi)\\r\\n\\r\\nGMP:\\r\\n* Fixed bug
#68419 (build error with gmp 4.1). (Remi)\\r\\n\\r\\nMcrypt:\\r\\n*
Fixed possible read after end of buffer and use after free.
(Dmitry)\\r\\n\\r\\nPDO_pgsql:\\r\\n* Fixed bug #67462
(PDO_PGSQL::beginTransaction() wrongly throws exception when not in
transaction) (Matteo)\\r\\n* Fixed bug #68351 (PDO::PARAM_BOOL and
ATTR_EMULATE_PREPARES misbehaving) (Matteo)\\r\\n\\r\\nSession:\\r\\n*
Fixed bug #68331 (Session custom storage callable functions not being
called) (Yasuo Ohgaki)\\r\\n\\r\\nSOAP:\\r\\n* Fixed bug #68361
(Segmentation fault on SoapClient::__getTypes).
(Laruence)\\r\\n\\r\\nzlib:\\r\\n* Fixed bug #53829 (Compiling PHP
with large file support will replace function gzopen by gzopen64)
(Sascha Kettler, Matteo)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1175718"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/147131.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98b77dc7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"php-5.6.4-2.fc21")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
