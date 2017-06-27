#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:047. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(72642);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/18 15:00:16 $");

  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-0067");
  script_bugtraq_id(65719, 65721, 65723, 65724, 65725, 65727, 65728, 65731);
  script_xref(name:"MDVSA", value:"2014:047");

  script_name(english:"Mandriva Linux Security Advisory : postgresql (MDVSA-2014:047)");
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
postgresql :

Granting a role without ADMIN OPTION is supposed to prevent the
grantee from adding or removing members from the granted role, but
this restriction was easily bypassed by doing SET ROLE first. The
security impact is mostly that a role member can revoke the access of
others, contrary to the wishes of his grantor. Unapproved role member
additions are a lesser concern, since an uncooperative role member
could provide most of his rights to others anyway by creating views or
SECURITY DEFINER functions (CVE-2014-0060).

The primary role of PL validator functions is to be called implicitly
during CREATE FUNCTION, but they are also normal SQL functions that a
user can call explicitly. Calling a validator on a function actually
written in some other language was not checked for and could be
exploited for privilege-escalation purposes. The fix involves adding a
call to a privilege-checking function in each validator function.
Non-core procedural languages will also need to make this change to
their own validator functions, if any (CVE-2014-0061).

If the name lookups come to different conclusions due to concurrent
activity, we might perform some parts of the DDL on a different table
than other parts. At least in the case of CREATE INDEX, this can be
used to cause the permissions checks to be performed against a
different table than the index creation, allowing for a privilege
escalation attack (CVE-2014-0062).

The MAXDATELEN constant was too small for the longest possible value
of type interval, allowing a buffer overrun in interval_out().
Although the datetime input functions were more careful about avoiding
buffer overrun, the limit was short enough to cause them to reject
some valid inputs, such as input containing a very long timezone name.
The ecpg library contained these vulnerabilities along with some of
its own (CVE-2014-0063).

Several functions, mostly type input functions, calculated an
allocation size without checking for overflow. If overflow did occur,
a too-small buffer would be allocated and then written past
(CVE-2014-0064).

Use strlcpy() and related functions to provide a clear guarantee that
fixed-size buffers are not overrun. Unlike the preceding items, it is
unclear whether these cases really represent live issues, since in
most cases there appear to be previous constraints on the size of the
input string. Nonetheless it seems prudent to silence all Coverity
warnings of this type (CVE-2014-0065).

There are relatively few scenarios in which crypt() could return NULL,
but contrib/chkpass would crash if it did. One practical case in which
this could be an issue is if libc is configured to refuse to execute
unapproved hashing algorithms (e.g., FIPS mode) (CVE-2014-0066).

Since the temporary server started by make check uses trust
authentication, another user on the same machine could connect to it
as database superuser, and then potentially exploit the privileges of
the operating-system user who started the tests. A future release will
probably incorporate changes in the testing procedure to prevent this
risk, but some public discussion is needed first. So for the moment,
just warn people against using make check when there are untrusted
users on the same machine (CVE-2014-0067).

This advisory provides the latest version of PostgreSQL that is not
vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.2/static/release-9-2-5.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.2/static/release-9-2-6.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.2/static/release-9-2-7.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ecpg9.2_6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pq9.2_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-plpgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64ecpg9.2_6-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64pq9.2_5-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-contrib-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-devel-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"postgresql9.2-docs-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-pl-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-plperl-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-plpgsql-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-plpython-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-pltcl-9.2.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-server-9.2.7-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
