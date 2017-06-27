#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:042. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(72595);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2012-3544", "CVE-2013-1571", "CVE-2013-1976", "CVE-2013-2067");
  script_bugtraq_id(59797, 59799, 60186, 60634);
  script_xref(name:"MDVSA", value:"2014:042");

  script_name(english:"Mandriva Linux Security Advisory : tomcat6 (MDVSA-2014:042)");
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
"Updated tomcat6 packages fix security vulnerabilities :

It was discovered that Tomcat incorrectly handled certain requests
submitted using chunked transfer encoding. A remote attacker could use
this flaw to cause the Tomcat server to stop responding, resulting in
a denial of service (CVE-2012-3544).

A frame injection in the Javadoc component in Oracle Java SE 7 Update
21 and earlier, 6 Update 45 and earlier, and 5.0 Update 45 and
earlier; JavaFX 2.2.21 and earlier; and OpenJDK 7 allows remote
attackers to affect integrity via unknown vectors related to Javadoc
(CVE-2013-1571).

A flaw was found in the way the tomcat6 init script handled the
tomcat6-initd.log log file. A malicious web application deployed on
Tomcat could use this flaw to perform a symbolic link attack to change
the ownership of an arbitrary system file to that of the tomcat user,
allowing them to escalate their privileges to root (CVE-2013-1976).

It was discovered that Tomcat incorrectly handled certain
authentication requests. A remote attacker could possibly use this
flaw to inject a request that would get executed with a victim's
credentials (CVE-2013-2067).

Note: With this update, tomcat6-initd.log has been moved from
/var/log/tomcat6/ to the /var/log/ directory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0082.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-systemv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-6.0.39-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-admin-webapps-6.0.39-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-docs-webapp-6.0.39-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-el-2.1-api-6.0.39-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-javadoc-6.0.39-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-jsp-2.1-api-6.0.39-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-lib-6.0.39-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-servlet-2.5-api-6.0.39-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-systemv-6.0.39-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"tomcat6-webapps-6.0.39-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
