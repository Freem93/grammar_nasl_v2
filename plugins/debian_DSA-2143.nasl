#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2143. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51530);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-3677", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3840");
  script_bugtraq_id(42598, 42599, 42633, 42646, 43676);
  script_osvdb_id(69001, 69387, 69390, 69392, 69393, 69394, 69395);
  script_xref(name:"DSA", value:"2143");

  script_name(english:"Debian DSA-2143-1 : mysql-dfsg-5.0 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the MySQL database
server. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2010-3677
    It was discovered that MySQL allows remote authenticated
    users to cause a denial of service (mysqld daemon crash)
    via a join query that uses a table with a unique SET
    column.

  - CVE-2010-3680
    It was discovered that MySQL allows remote authenticated
    users to cause a denial of service (mysqld daemon crash)
    by creating temporary tables while using InnoDB, which
    triggers an assertion failure.

  - CVE-2010-3681
    It was discovered that MySQL allows remote authenticated
    users to cause a denial of service (mysqld daemon crash)
    by using the HANDLER interface and performing 'alternate
    reads from two indexes on a table,' which triggers an
    assertion failure.

  - CVE-2010-3682
    It was discovered that MySQL incorrectly handled use of
    EXPLAIN with certain queries. An authenticated user
    could crash the server.

  - CVE-2010-3833
    It was discovered that MySQL incorrectly handled
    propagation during evaluation of arguments to
    extreme-value functions. An authenticated user could
    crash the server.

  - CVE-2010-3834
    It was discovered that MySQL incorrectly handled
    materializing a derived table that required a temporary
    table for grouping. An authenticated user could crash
    the server.

  - CVE-2010-3835
    It was discovered that MySQL incorrectly handled certain
    user-variable assignment expressions that are evaluated
    in a logical expression context. An authenticated user
    could crash the server.

  - CVE-2010-3836
    It was discovered that MySQL incorrectly handled
    pre-evaluation of LIKE predicates during view
    preparation. An authenticated user could crash the
    server.

  - CVE-2010-3837
    It was discovered that MySQL incorrectly handled using
    GROUP_CONCAT() and WITH ROLLUP together. An
    authenticated user could crash the server.

  - CVE-2010-3838
    It was discovered that MySQL incorrectly handled certain
    queries using a mixed list of numeric and LONGBLOB
    arguments to the GREATEST() or LEAST() functions. An
    authenticated user could crash the server.

  - CVE-2010-3840
    It was discovered that MySQL incorrectly handled
    improper WKB data passed to the PolyFromWKB() function.
    An authenticated user could crash the server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2143"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-dfsg-5.0 packages.

For the stable distribution (lenny), these problems have been fixed in
version 5.0.51a-24+lenny5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"mysql-dfsg-5.0", reference:"5.0.51a-24+lenny5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
