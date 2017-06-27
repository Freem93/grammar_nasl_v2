#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:190. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82561);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/03 13:28:13 $");

  script_cve_id("CVE-2014-9041", "CVE-2014-9042", "CVE-2014-9043", "CVE-2014-9045");
  script_bugtraq_id(71373, 71383, 71389);
  script_xref(name:"MDVSA", value:"2015:190");

  script_name(english:"Mandriva Linux Security Advisory : owncloud (MDVSA-2015:190)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in 
owncloud :

  - Login bypass when using user_ldap due to unauthenticated
    binds (oC-SA-2014-020)

  - Login bypass when using the external FTP user backend
    (oC-SA-2014-022)

  - CSRF in bookmarks application (oC-SA-2014-027)

  - Stored XSS in bookmarks application (oC-SA-2014-028)

  - Multiple stored XSS in contacts application
    (oC-SA-2015-001)

  - Multiple stored XSS in documents application
    (oC-SA-2015-002)

  - Bypass of file blacklist (oC-SA-2015-004)

The updated packages have been upgraded to the 5.0.19 version where
these security flaws has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/changelog/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-004"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected owncloud package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:owncloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"owncloud-5.0.19-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
