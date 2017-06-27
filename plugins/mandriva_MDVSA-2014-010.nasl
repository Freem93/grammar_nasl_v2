#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:010. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(72024);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/01/22 11:42:16 $");

  script_cve_id("CVE-2013-0179", "CVE-2013-7239", "CVE-2013-7290", "CVE-2013-7291");
  script_bugtraq_id(64559, 64978, 64988, 64989);
  script_xref(name:"MDVSA", value:"2014:010");

  script_name(english:"Mandriva Linux Security Advisory : memcached (MDVSA-2014:010)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in
memcached :

The process_bin_delete function in memcached.c in memcached 1.4.4 and
other versions before 1.4.17, when running in verbose mode, allows
remote attackers to cause a denial of service (segmentation fault) via
a request to delete a key, which does not account for the lack of a
null terminator in the key and triggers a buffer over-read when
printing to stderr (CVE-2013-0179).

memcached before 1.4.17 allows remote attackers to bypass
authentication by sending an invalid request with SASL credentials,
then sending another request with incorrect SASL credentials
(CVE-2013-7239).

The do_item_get function in items.c in memcached 1.4.4 and other
versions before 1.4.17, when running in verbose mode, allows remote
attackers to cause a denial of service (segmentation fault) via a
request to delete a key, which does not account for the lack of a null
terminator in the key and triggers a buffer over-read when printing to
stderr, a different vulnerability than CVE-2013-0179 (CVE-2013-7290).

memcached before 1.4.17, when running in verbose mode, allows remote
attackers to cause a denial of service (crash) via a request that
triggers an unbounded key print during logging, related to an issue
that was quickly grepped out of the source tree, a different
vulnerability than CVE-2013-0179 and CVE-2013-7290 (CVE-2013-7291).

The updated packages have been upgraded to the 1.4.17 version which is
unaffected by these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/memcached/wiki/ReleaseNotes1417"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected memcached and / or memcached-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:memcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:memcached-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"memcached-1.4.17-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"memcached-devel-1.4.17-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
