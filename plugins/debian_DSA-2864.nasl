#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2864. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(72610);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-0067");
  script_bugtraq_id(65728);
  script_osvdb_id(103544, 103545, 103546, 103547, 103548, 103549, 103550, 103551);
  script_xref(name:"DSA", value:"2864");

  script_name(english:"Debian DSA-2864-1 : postgresql-8.4 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various vulnerabilities were discovered in PostgreSQL :

  - CVE-2014-0060 Shore up GRANT ... WITH ADMIN OPTION
    restrictions (Noah Misch)
    Granting a role without ADMIN OPTION is supposed to
    prevent the grantee from adding or removing members from
    the granted role, but this restriction was easily
    bypassed by doing SET ROLE first. The security impact is
    mostly that a role member can revoke the access of
    others, contrary to the wishes of his grantor.
    Unapproved role member additions are a lesser concern,
    since an uncooperative role member could provide most of
    his rights to others anyway by creating views or
    SECURITY DEFINER functions.

  - CVE-2014-0061 Prevent privilege escalation via manual
    calls to PL validator functions (Andres Freund)

    The primary role of PL validator functions is to be
    called implicitly during CREATE FUNCTION, but they are
    also normal SQL functions that a user can call
    explicitly. Calling a validator on a function actually
    written in some other language was not checked for and
    could be exploited for privilege-escalation purposes.
    The fix involves adding a call to a privilege-checking
    function in each validator function. Non-core procedural
    languages will also need to make this change to their
    own validator functions, if any.

  - CVE-2014-0062 Avoid multiple name lookups during table
    and index DDL (Robert Haas, Andres Freund)

    If the name lookups come to different conclusions due to
    concurrent activity, we might perform some parts of the
    DDL on a different table than other parts. At least in
    the case of CREATE INDEX, this can be used to cause the
    permissions checks to be performed against a different
    table than the index creation, allowing for a privilege
    escalation attack.

  - CVE-2014-0063 Prevent buffer overrun with long datetime
    strings (Noah Misch)

    The MAXDATELEN constant was too small for the longest
    possible value of type interval, allowing a buffer
    overrun in interval_out(). Although the datetime input
    functions were more careful about avoiding buffer
    overrun, the limit was short enough to cause them to
    reject some valid inputs, such as input containing a
    very long timezone name. The ecpg library contained
    these vulnerabilities along with some of its own.

  - CVE-2014-0064 Prevent buffer overrun due to integer
    overflow in size calculations (Noah Misch, Heikki
    Linnakangas)

    Several functions, mostly type input functions,
    calculated an allocation size without checking for
    overflow. If overflow did occur, a too-small buffer
    would be allocated and then written past.

  - CVE-2014-0065 Prevent overruns of fixed-size buffers
    (Peter Eisentraut, Jozef Mlich)

    Use strlcpy() and related functions to provide a clear
    guarantee that fixed-size buffers are not overrun.
    Unlike the preceding items, it is unclear whether these
    cases really represent live issues, since in most cases
    there appear to be previous constraints on the size of
    the input string. Nonetheless it seems prudent to
    silence all Coverity warnings of this type.

  - CVE-2014-0066 Avoid crashing if crypt() returns NULL
    (Honza Horak, Bruce Momjian)

    There are relatively few scenarios in which crypt()
    could return NULL, but contrib/chkpass would crash if it
    did. One practical case in which this could be an issue
    is if libc is configured to refuse to execute unapproved
    hashing algorithms (e.g., 'FIPS mode').

  - CVE-2014-0067 Document risks of make check in the
    regression testing instructions (Noah Misch, Tom Lane)

    Since the temporary server started by make check uses
    'trust' authentication, another user on the same machine
    could connect to it as database superuser, and then
    potentially exploit the privileges of the
    operating-system user who started the tests. A future
    release will probably incorporate changes in the testing
    procedure to prevent this risk, but some public
    discussion is needed first. So for the moment, just warn
    people against using make check when there are untrusted
    users on the same machine."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/postgresql-8.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2864"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-8.4 packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 8.4.20-0squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"libecpg-compat3", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg-dev", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg6", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpgtypes3", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq-dev", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq5", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-8.4", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client-8.4", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib-8.4", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc-8.4", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plperl-8.4", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plpython-8.4", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-pltcl-8.4", reference:"8.4.20-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-server-dev-8.4", reference:"8.4.20-0squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
